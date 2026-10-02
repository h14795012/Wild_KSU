#include "wksu_freeze.h"

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

enum wksu_hold_state {
    WH_QUEUED,
    WH_COPYING,
    WH_PARKED,
    WH_RELEASED,
    WH_ABORTED,
};

struct wksu_hold_ctx {
    struct callback_head work;
    struct kref refs;
    struct task_struct *target;
    struct mm_struct *mm;
    wait_queue_head_t wait;
    raw_spinlock_t lock;
    enum wksu_hold_state state;
    int error;
    ktime_t acquire_deadline;
    ktime_t lease_deadline;
    __u32 lease_us;
    __u32 nr;
    struct wksu_hold_field fields[WKSU_HOLD_MAX_FIELDS];
    struct wksu_hold_snapshot snapshot;
};

static void wksu_hold_ctx_release(struct kref *ref)
{
    struct wksu_hold_ctx *ctx = container_of(ref, struct wksu_hold_ctx, refs);
    if (ctx->mm)
        mmdrop(ctx->mm);
    if (ctx->target)
        put_task_struct(ctx->target);
    kfree(ctx);
}

static inline void wksu_hold_get(struct wksu_hold_ctx *ctx)
{
    if (ctx)
        kref_get(&ctx->refs);
}

static inline void wksu_hold_put(struct wksu_hold_ctx *ctx)
{
    if (ctx)
        kref_put(&ctx->refs, wksu_hold_ctx_release);
}

/*
 * Work function executed by the target task itself right before returning to EL0 user mode.
 * Runs in sleepable task context with interrupts enabled, completely eliminating cross-CPU
 * scheduler deadlocks or RCU stalls.
 */
static void wksu_hold_work_func(struct callback_head *cb)
{
    struct wksu_hold_ctx *ctx = container_of(cb, struct wksu_hold_ctx, work);
    unsigned long flags;
    int copy_err = 0;
    __u32 i;

    /* Safety checks */
    if (irqs_disabled() || in_atomic()) {
        raw_spin_lock_irqsave(&ctx->lock, flags);
        ctx->error = -EBUSY;
        ctx->state = WH_ABORTED;
        raw_spin_unlock_irqrestore(&ctx->lock, flags);
        wake_up_all(&ctx->wait);
        wksu_hold_put(ctx);
        return;
    }

    raw_spin_lock_irqsave(&ctx->lock, flags);
    if (ctx->state != WH_QUEUED || current->mm != ctx->mm || (current->flags & PF_EXITING)) {
        ctx->error = -ECANCELED;
        ctx->state = WH_ABORTED;
        raw_spin_unlock_irqrestore(&ctx->lock, flags);
        wake_up_all(&ctx->wait);
        wksu_hold_put(ctx);
        return;
    }

    if (ktime_compare(ktime_get(), ctx->acquire_deadline) >= 0) {
        ctx->error = -ETIMEDOUT;
        ctx->state = WH_ABORTED;
        raw_spin_unlock_irqrestore(&ctx->lock, flags);
        wake_up_all(&ctx->wait);
        wksu_hold_put(ctx);
        return;
    }

    ctx->state = WH_COPYING;
    ctx->lease_deadline = ktime_add_us(ktime_get(), ctx->lease_us);
    raw_spin_unlock_irqrestore(&ctx->lock, flags);

    /* 1. Sample live TLS and pt_regs in target context */
    preempt_disable();
#if defined(__aarch64__)
    ctx->snapshot.tls = (u64)*task_user_tls(current);
    if (task_pt_regs(current)) {
        ctx->snapshot.regs = task_pt_regs(current)->user_regs;
    }
#endif
    preempt_enable();

    /* 2. Sample requested memory fields using copy_from_user_nofault in current mm */
    for (i = 0; i < ctx->nr; i++) {
        const void __user *src = (const void __user *)(unsigned long)ctx->fields[i].addr;

        if (ktime_compare(ktime_get(), ctx->lease_deadline) >= 0) {
            copy_err = -ETIMEDOUT;
            break;
        }

        if (copy_from_user_nofault(ctx->snapshot.data[i], src, ctx->fields[i].len)) {
            copy_err = -EFAULT;
            break;
        }
        ctx->snapshot.len[i] = ctx->fields[i].len;
    }
    ctx->snapshot.nr = ctx->nr;
    ctx->snapshot.sample_ns = ktime_get_ns();

    raw_spin_lock_irqsave(&ctx->lock, flags);
    if (copy_err) {
        ctx->error = copy_err;
        ctx->state = WH_ABORTED;
    } else {
        ctx->state = WH_PARKED;
    }
    raw_spin_unlock_irqrestore(&ctx->lock, flags);
    wake_up_all(&ctx->wait);

    /* 3. Short park window until caller acknowledges or lease expires */
    if (!copy_err) {
        ktime_t rem = ktime_sub(ctx->lease_deadline, ktime_get());
        if (ktime_to_ns(rem) > 0) {
            wait_event_interruptible_hrtimeout(ctx->wait,
                READ_ONCE(ctx->state) != WH_PARKED, rem);
        }
    }

    raw_spin_lock_irqsave(&ctx->lock, flags);
    if (ctx->state == WH_PARKED) {
        /* Lease expired before caller released; auto self-thaw */
        ctx->state = WH_ABORTED;
        ctx->error = -ETIMEDOUT;
    }
    raw_spin_unlock_irqrestore(&ctx->lock, flags);
    wake_up_all(&ctx->wait);

    wksu_hold_put(ctx);
}

int wksu_capture_consistent_snapshot(struct task_struct *target,
                                    struct mm_struct *mm,
                                    const struct wksu_hold_field *fields,
                                    __u32 nr,
                                    struct wksu_hold_snapshot *out,
                                    __u32 timeout_us,
                                    __u32 lease_us)
{
    struct wksu_hold_ctx *ctx;
    unsigned long flags;
    ktime_t remaining;
    long waited;
    int ret = 0;
    __u32 i;

    if (!target || !mm || !out || nr > WKSU_HOLD_MAX_FIELDS)
        return -EINVAL;
    if (nr > 0 && !fields)
        return -EINVAL;
    if (target == current || (READ_ONCE(target->flags) & PF_KTHREAD))
        return -EINVAL;

    if (timeout_us == 0 || timeout_us > 50000)
        timeout_us = 2000;
    if (lease_us == 0 || lease_us > 2000)
        lease_us = 200;

    for (i = 0; i < nr; i++) {
        if (fields[i].len == 0 || fields[i].len > WKSU_HOLD_FIELD_SIZE)
            return -EINVAL;
        if (fields[i].addr > U64_MAX - fields[i].len)
            return -EINVAL;
    }

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    kref_init(&ctx->refs);
    raw_spin_lock_init(&ctx->lock);
    init_waitqueue_head(&ctx->wait);

    get_task_struct(target);
    mmgrab(mm);
    ctx->target = target;
    ctx->mm = mm;
    ctx->state = WH_QUEUED;
    ctx->lease_us = lease_us;
    ctx->nr = nr;
    if (nr > 0)
        memcpy(ctx->fields, fields, nr * sizeof(*fields));

    ctx->acquire_deadline = ktime_add_us(ktime_get(), timeout_us);
    init_task_work(&ctx->work, wksu_hold_work_func);

    /* Reference held for the queued work */
    wksu_hold_get(ctx);

    ret = task_work_add(target, &ctx->work, TWA_RESUME);
    if (ret) {
        wksu_hold_put(ctx);
        wksu_hold_put(ctx);
        return ret;
    }

    remaining = ktime_sub(ctx->acquire_deadline, ktime_get());
    if (ktime_to_ns(remaining) <= 0) {
        task_work_cancel(target, wksu_hold_work_func);
        wksu_hold_put(ctx);
        return -ETIMEDOUT;
    }

    waited = wait_event_interruptible_hrtimeout(ctx->wait,
        READ_ONCE(ctx->state) != WH_QUEUED && READ_ONCE(ctx->state) != WH_COPYING,
        remaining);

    raw_spin_lock_irqsave(&ctx->lock, flags);
    if (waited < 0) {
        ret = (waited == -ETIME) ? -ETIMEDOUT : (int)waited;
    } else if (ctx->state != WH_PARKED) {
        ret = ctx->error ? ctx->error : -ECANCELED;
    } else if (ktime_compare(ktime_get(), ctx->acquire_deadline) >= 0 ||
               ktime_compare(ktime_get(), ctx->lease_deadline) >= 0) {
        ret = -ETIMEDOUT;
    } else {
        ret = 0;
    }

    if (ret == 0) {
        *out = ctx->snapshot;
        ctx->state = WH_RELEASED;
        raw_spin_unlock_irqrestore(&ctx->lock, flags);
        wake_up_all(&ctx->wait);
    } else {
        ctx->state = WH_ABORTED;
        if (!ctx->error)
            ctx->error = ret;
        raw_spin_unlock_irqrestore(&ctx->lock, flags);
        task_work_cancel(target, wksu_hold_work_func);
        wake_up_all(&ctx->wait);
    }

    wksu_hold_put(ctx);
    return ret;
}
