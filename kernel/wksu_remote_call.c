#include "wksu_remote_call.h"

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>

#define WKSU_BRK_IMM_RETURN 0x574b  /* 'W' 'K': brk #0x574b */
#define WKSU_MAX_RC_SESSIONS 8

enum rc_phase {
    RC_PHASE_QUEUED,
    RC_PHASE_ARMED,
    RC_PHASE_RESTORING,
    RC_PHASE_QUIESCED,
    RC_PHASE_ABORTED,
};

enum rc_reason {
    RC_REASON_NONE,
    RC_REASON_RETURN,
    RC_REASON_TIMEOUT,
    RC_REASON_FAULT,
    RC_REASON_CANCEL,
};

struct wksu_rc_session {
    struct callback_head work;
    struct kref refs;
    struct task_struct *target;
    struct mm_struct *mm;
    wait_queue_head_t wait;
    raw_spinlock_t lock;

    atomic_t phase;
    atomic_t reason;

    struct pt_regs saved_regs;
    struct user_fpsimd_state saved_fpsimd;

    struct wksu_remote_call_cmd cmd;
};

static struct wksu_rc_session *g_rc_sessions[WKSU_MAX_RC_SESSIONS];
static DEFINE_SPINLOCK(g_rc_sessions_lock);

static void wksu_rc_session_release(struct kref *ref)
{
    struct wksu_rc_session *sess = container_of(ref, struct wksu_rc_session, refs);
    if (sess->mm)
        mmdrop(sess->mm);
    if (sess->target)
        put_task_struct(sess->target);
    kfree(sess);
}

static inline void wksu_session_get(struct wksu_rc_session *sess)
{
    if (sess)
        kref_get(&sess->refs);
}

static inline void wksu_session_put(struct wksu_rc_session *sess)
{
    if (sess)
        kref_put(&sess->refs, wksu_rc_session_release);
}

/*
 * Register session with exclusive per-target check and explicit reference ownership.
 */
static int wksu_register_session(struct wksu_rc_session *sess)
{
    unsigned long flags;
    int i, free_idx = -1, ret = -EBUSY;

    spin_lock_irqsave(&g_rc_sessions_lock, flags);
    for (i = 0; i < WKSU_MAX_RC_SESSIONS; i++) {
        if (g_rc_sessions[i]) {
            if (g_rc_sessions[i]->target == sess->target) {
                /* Target already has an active session */
                spin_unlock_irqrestore(&g_rc_sessions_lock, flags);
                return -EBUSY;
            }
        } else if (free_idx < 0) {
            free_idx = i;
        }
    }

    if (free_idx >= 0) {
        g_rc_sessions[free_idx] = sess;
        wksu_session_get(sess); /* Registry holds its own reference */
        ret = 0;
    }
    spin_unlock_irqrestore(&g_rc_sessions_lock, flags);
    return ret;
}

static void wksu_unregister_session_locked(struct wksu_rc_session *sess)
{
    int i;
    for (i = 0; i < WKSU_MAX_RC_SESSIONS; i++) {
        if (g_rc_sessions[i] == sess) {
            g_rc_sessions[i] = NULL;
            wksu_session_put(sess); /* Release registry reference */
            break;
        }
    }
}

static void wksu_unregister_session(struct wksu_rc_session *sess)
{
    unsigned long flags;

    spin_lock_irqsave(&g_rc_sessions_lock, flags);
    wksu_unregister_session_locked(sess);
    spin_unlock_irqrestore(&g_rc_sessions_lock, flags);
}

/*
 * Returns a referenced session pointer if target matches and session is active.
 * Caller MUST call wksu_session_put(found) when done!
 */
static struct wksu_rc_session *wksu_get_active_session(struct task_struct *task)
{
    unsigned long flags;
    struct wksu_rc_session *found = NULL;
    int i;

    spin_lock_irqsave(&g_rc_sessions_lock, flags);
    for (i = 0; i < WKSU_MAX_RC_SESSIONS; i++) {
        if (g_rc_sessions[i] && g_rc_sessions[i]->target == task) {
            found = g_rc_sessions[i];
            wksu_session_get(found);
            break;
        }
    }
    spin_unlock_irqrestore(&g_rc_sessions_lock, flags);
    return found;
}

static void wksu_restore_session_context(struct wksu_rc_session *sess, struct pt_regs *regs)
{
    /* 1. Restore architectural general purpose registers, SP, PC, and PSTATE */
    memcpy(regs, &sess->saved_regs, sizeof(*regs));

    /* 2. Restore user FPSIMD state */
    fpsimd_update_current_state(&sess->saved_fpsimd);
}

static int wksu_break_return_handler(struct pt_regs *regs, unsigned int esr)
{
    struct wksu_rc_session *sess;
    int current_phase;

    if (!user_mode(regs))
        return DBG_HOOK_ERROR;

    sess = wksu_get_active_session(current);
    if (!sess)
        return DBG_HOOK_ERROR;

    /* Validate gadget address to prevent swallowing unrelated break instructions */
    if (regs->pc != sess->cmd.gadget_addr) {
        wksu_session_put(sess);
        return DBG_HOOK_ERROR;
    }

    current_phase = atomic_read(&sess->phase);
    if (current_phase != RC_PHASE_ARMED && current_phase != RC_PHASE_QUIESCED) {
        wksu_session_put(sess);
        return DBG_HOOK_HANDLED;
    }

    /*
     * Central Invariant: Even if caller timed out (RC_REASON_TIMEOUT),
     * we MUST restore original registers so the target thread does not crash!
     */
    if (atomic_cmpxchg(&sess->reason, RC_REASON_NONE, RC_REASON_RETURN) == RC_REASON_NONE) {
        atomic_set(&sess->phase, RC_PHASE_RESTORING);
        sess->cmd.ret_x0 = regs->regs[0];
        sess->cmd.status = WKSU_RC_SUCCESS;
    }

    /* Perform guaranteed restoration */
    wksu_restore_session_context(sess, regs);

    atomic_set(&sess->phase, RC_PHASE_QUIESCED);
    wake_up_all(&sess->wait);

    /* Cleanly unregister and drop references */
    wksu_unregister_session(sess);
    wksu_session_put(sess);

    return DBG_HOOK_HANDLED;
}

static struct break_hook wksu_return_break_hook = {
    .fn = wksu_break_return_handler,
    .imm = WKSU_BRK_IMM_RETURN,
    .mask = 0,
};

static void wksu_rc_work_func(struct callback_head *cb)
{
    struct wksu_rc_session *sess = container_of(cb, struct wksu_rc_session, work);
    struct pt_regs *regs;
    unsigned long user_sp;
    int i;

    /* Safety checks: not in atomic/irq-disabled, not exiting, mm valid, no pending signals */
    if (irqs_disabled() || in_atomic() || (current->flags & PF_EXITING) ||
        current->mm != sess->mm || signal_pending(current)) {
        if (atomic_cmpxchg(&sess->reason, RC_REASON_NONE, RC_REASON_FAULT) == RC_REASON_NONE) {
            sess->cmd.status = WKSU_RC_ERR_BUSY;
            atomic_set(&sess->phase, RC_PHASE_QUIESCED);
            wake_up_all(&sess->wait);
        }
        wksu_session_put(sess);
        return;
    }

    regs = task_pt_regs(current);
    /* Explicitly ensure 64-bit user mode (reject compat / aarch32) */
    if (!regs || !user_mode(regs) || compat_user_mode(regs)) {
        if (atomic_cmpxchg(&sess->reason, RC_REASON_NONE, RC_REASON_FAULT) == RC_REASON_NONE) {
            sess->cmd.status = WKSU_RC_ERR_INVALID;
            atomic_set(&sess->phase, RC_PHASE_QUIESCED);
            wake_up_all(&sess->wait);
        }
        wksu_session_put(sess);
        return;
    }

    if (atomic_read(&sess->phase) != RC_PHASE_QUEUED) {
        wksu_session_put(sess);
        return;
    }

    /* 1. Take complete snapshot of user register frame */
    memcpy(&sess->saved_regs, regs, sizeof(*regs));

    /* 2. Flush and preserve live user FP/SIMD state */
    fpsimd_preserve_current_state();
    memcpy(&sess->saved_fpsimd, &current->thread.uw.fpsimd_state, sizeof(sess->saved_fpsimd));

    /* 3. AAPCS64 Stack Management:
     * Pre-allocate 256 bytes frame cushion below current SP, 16-byte aligned.
     */
    user_sp = regs->sp;
    user_sp = (user_sp - 256) & ~0xFULL;
    regs->sp = user_sp;

    /* 4. Prepare parameters X0-X7 (do NOT clobber X8, which is AAPCS64 indirect result) */
    for (i = 0; i < 8; i++) {
        regs->regs[i] = sess->cmd.args[i];
    }

    /* Set Link Register (X30) to return gadget */
    regs->regs[30] = sess->cmd.gadget_addr;

    /* Target PC */
    regs->pc = sess->cmd.func_addr;

    /* Clear Single-Step bit in PSTATE */
    regs->pstate &= ~PSR_SS_BIT;

    /* 5. Commit transition to ARMED */
    atomic_set(&sess->phase, RC_PHASE_ARMED);

    wksu_session_put(sess);
}

int wksu_execute_remote_call(struct task_struct *target,
                            struct mm_struct *mm,
                            struct wksu_remote_call_cmd *cmd)
{
    struct wksu_rc_session *sess;
    long timeout_jiffies;
    int ret = 0;

    if (!target || !mm || !cmd)
        return -EINVAL;

    if (target == current || (target->flags & PF_KTHREAD))
        return -EINVAL;

    if (!cmd->func_addr || !cmd->gadget_addr)
        return -EINVAL;

    if (cmd->timeout_ms == 0 || cmd->timeout_ms > 5000)
        cmd->timeout_ms = 100;

    sess = kzalloc(sizeof(*sess), GFP_KERNEL);
    if (!sess)
        return -ENOMEM;

    kref_init(&sess->refs);
    raw_spin_lock_init(&sess->lock);
    init_waitqueue_head(&sess->wait);
    sess->target = target;
    get_task_struct(target);
    sess->mm = mm;
    mmgrab(mm);
    sess->cmd = *cmd;
    atomic_set(&sess->phase, RC_PHASE_QUEUED);
    atomic_set(&sess->reason, RC_REASON_NONE);

    sess->work.func = wksu_rc_work_func;

    if (wksu_register_session(sess)) {
        ret = -EBUSY;
        goto out_put;
    }

    /* Take ref for the queued task_work */
    wksu_session_get(sess);

    ret = task_work_add(target, &sess->work, TWA_RESUME);
    if (ret) {
        wksu_session_put(sess);
        wksu_unregister_session(sess);
        goto out_put;
    }

    kick_process(target);

    timeout_jiffies = msecs_to_jiffies(cmd->timeout_ms + 100);
    wait_event_interruptible_timeout(sess->wait,
        atomic_read(&sess->phase) == RC_PHASE_QUIESCED,
        timeout_jiffies);

    if (atomic_read(&sess->phase) != RC_PHASE_QUIESCED) {
        if (atomic_cmpxchg(&sess->reason, RC_REASON_NONE, RC_REASON_TIMEOUT) == RC_REASON_NONE) {
            sess->cmd.status = WKSU_RC_ERR_TIMEOUT;
            /* Note: We do NOT unregister immediately here if target is ARMED;
             * the break hook will restore registers when target completes. */
            kick_process(target);
        }
    }

    *cmd = sess->cmd;
    ret = 0;

    /* If session never reached ARMED (e.g. aborted during queueing), unregister now */
    if (atomic_read(&sess->phase) != RC_PHASE_ARMED) {
        wksu_unregister_session(sess);
    }

out_put:
    wksu_session_put(sess);
    return ret;
}

int wksu_remote_call_init(void)
{
    register_user_break_hook(&wksu_return_break_hook);
    pr_info("wksu_rc: break hook registered for imm 0x%04x\n", WKSU_BRK_IMM_RETURN);
    return 0;
}

void wksu_remote_call_exit(void)
{
    unregister_user_break_hook(&wksu_return_break_hook);
    pr_info("wksu_rc: break hook unregistered\n");
}
