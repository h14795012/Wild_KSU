#include <linux/err.h>
#include <linux/hw_breakpoint.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include "audit.h"
#include "breakpoint.h"

#define WKSU_BREAKPOINT_RING_SIZE 256
#define WKSU_BREAKPOINT_MAX_SLOTS 16
#define WKSU_BREAKPOINT_MAX_TARGETS 128
#define WKSU_BREAKPOINT_MAX_WAIT_MS 60000

struct wksu_breakpoint {
	bool used;
	bool enabled;
	u32 id;
	u32 flags;
	u32 len;
	u32 type;
	s32 requested_pid;
	s32 target_pid;
	s32 target_tgid;
	u64 addr;
	int last_error;
	atomic64_t hits;
	u32 event_count;
	struct perf_event *events[WKSU_BREAKPOINT_MAX_TARGETS];
	pid_t event_pids[WKSU_BREAKPOINT_MAX_TARGETS];
	char name[WKSU_BREAKPOINT_NAME_LEN];
};

static DEFINE_MUTEX(wksu_breakpoint_lock);
static struct wksu_breakpoint wksu_breakpoints[WKSU_BREAKPOINT_MAX_SLOTS];
static u32 wksu_breakpoint_next_id = 1;

static DEFINE_SPINLOCK(wksu_breakpoint_event_lock);
static struct wksu_breakpoint_event
	wksu_breakpoint_ring[WKSU_BREAKPOINT_RING_SIZE];
static u32 wksu_breakpoint_head;
static u32 wksu_breakpoint_tail;
static u32 wksu_breakpoint_count;
static u64 wksu_breakpoint_next_seq;
static u64 wksu_breakpoint_dropped;
static DECLARE_WAIT_QUEUE_HEAD(wksu_breakpoint_wait);

extern bool wksu_is_pid_hidden(int pid);

static bool wksu_breakpoint_type_valid(u32 type)
{
	switch (type) {
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW:
	case HW_BREAKPOINT_X:
		return true;
	default:
		return false;
	}
}

static bool wksu_breakpoint_len_valid(u32 len)
{
	return len == 1 || len == 2 || len == 4 || len == 8;
}

static bool wksu_breakpoint_op_mutates(u32 op)
{
	return op == WKSU_BREAKPOINT_ADD ||
	       op == WKSU_BREAKPOINT_REMOVE ||
	       op == WKSU_BREAKPOINT_CLEAR ||
	       op == WKSU_BREAKPOINT_ENABLE ||
	       op == WKSU_BREAKPOINT_REFRESH ||
	       op == WKSU_BREAKPOINT_READ ||
	       op == WKSU_BREAKPOINT_WAIT;
}

static u32 wksu_breakpoint_alloc_id(void)
{
	u32 id = wksu_breakpoint_next_id++;

	if (!wksu_breakpoint_next_id)
		wksu_breakpoint_next_id = 1;
	if (!id)
		id = wksu_breakpoint_next_id++;

	return id;
}

static struct wksu_breakpoint *wksu_breakpoint_find_locked(u32 id)
{
	int i;

	for (i = 0; i < WKSU_BREAKPOINT_MAX_SLOTS; i++) {
		if (wksu_breakpoints[i].used && wksu_breakpoints[i].id == id)
			return &wksu_breakpoints[i];
	}

	return NULL;
}

static struct wksu_breakpoint *wksu_breakpoint_free_slot_locked(void)
{
	int i;

	for (i = 0; i < WKSU_BREAKPOINT_MAX_SLOTS; i++) {
		if (!wksu_breakpoints[i].used)
			return &wksu_breakpoints[i];
	}

	return NULL;
}

static bool wksu_breakpoint_duplicate_locked(s32 target_pid, s32 target_tgid,
					     u64 addr, u32 len, u32 type,
					     u32 flags)
{
	int i;
	bool thread_scope = flags & WKSU_BREAKPOINT_F_THREAD;

	for (i = 0; i < WKSU_BREAKPOINT_MAX_SLOTS; i++) {
		struct wksu_breakpoint *bp = &wksu_breakpoints[i];
		bool bp_thread_scope;

		if (!bp->used)
			continue;
		if (bp->addr != addr || bp->len != len || bp->type != type)
			continue;

		bp_thread_scope = bp->flags & WKSU_BREAKPOINT_F_THREAD;
		if (thread_scope) {
			if (bp_thread_scope && bp->target_pid == target_pid)
				return true;
			if (!bp_thread_scope && bp->target_tgid == target_tgid)
				return true;
		} else if (bp->target_tgid == target_tgid) {
			return true;
		}
	}

	return false;
}

static void wksu_breakpoint_unregister_event_array(struct perf_event **events,
						   u32 event_count)
{
	u32 i;

	if (!events)
		return;

	for (i = 0; i < event_count; i++) {
		if (!events[i])
			continue;
		unregister_hw_breakpoint(events[i]);
		events[i] = NULL;
	}
}

static void wksu_breakpoint_unregister_locked(struct wksu_breakpoint *bp)
{
	if (!bp)
		return;

	wksu_breakpoint_unregister_event_array(bp->events, bp->event_count);
	bp->event_count = 0;
	bp->enabled = false;
}

static void wksu_breakpoint_enable_event_array(struct perf_event **events,
					       u32 event_count, bool enable)
{
	u32 i;

	for (i = 0; i < event_count; i++) {
		if (!events[i])
			continue;
		if (enable)
			perf_event_enable(events[i]);
		else
			perf_event_disable(events[i]);
	}
}

static bool wksu_breakpoint_task_list_has_pid(struct task_struct **tasks,
					     u32 task_count, pid_t pid)
{
	u32 i;

	for (i = 0; i < task_count; i++) {
		if (task_pid_nr(tasks[i]) == pid)
			return true;
	}

	return false;
}

static bool wksu_breakpoint_has_event_pid(struct wksu_breakpoint *bp, pid_t pid)
{
	u32 i;

	if (!bp)
		return false;

	for (i = 0; i < bp->event_count; i++) {
		if (bp->events[i] && bp->event_pids[i] == pid)
			return true;
	}

	return false;
}

static void wksu_breakpoint_fill_info(struct wksu_breakpoint *bp,
				      struct wksu_breakpoint_info *info)
{
	memset(info, 0, sizeof(*info));
	info->id = bp->id;
	info->flags = bp->flags;
	info->pid = bp->requested_pid;
	info->tgid = bp->target_tgid;
	info->addr = bp->addr;
	info->len = bp->len;
	info->type = bp->type;
	info->task_count = bp->event_count;
	info->enabled = bp->enabled ? 1 : 0;
	info->last_error = bp->last_error;
	info->hits = atomic64_read(&bp->hits);
	strscpy(info->name, bp->name, sizeof(info->name));
}

static void wksu_breakpoint_push_event(struct wksu_breakpoint *bp,
				       struct perf_event *event,
				       struct perf_sample_data *data,
				       struct pt_regs *regs)
{
	struct wksu_breakpoint_event *entry;
	unsigned long flags;
	u64 pc = 0;
	u64 far = 0;
	u64 sp = 0;
	u64 lr = 0;
	u64 pstate = 0;
	u64 hits;
	int i;

	if (!bp || !bp->used)
		return;

	if (bp->flags & WKSU_BREAKPOINT_F_THREAD) {
		if (task_pid_nr(current) != bp->target_pid)
			return;
	} else if (task_tgid_nr(current) != bp->target_tgid) {
		return;
	}

#ifdef CONFIG_HAVE_HW_BREAKPOINT
	far = counter_arch_bp(event)->trigger;
#endif
	if (!far && data)
		far = data->addr;

	if (regs) {
		pc = instruction_pointer(regs);
		sp = regs->sp;
		lr = regs->regs[30];
		pstate = regs->pstate;
	}

	hits = atomic64_inc_return(&bp->hits);

	spin_lock_irqsave(&wksu_breakpoint_event_lock, flags);
	entry = &wksu_breakpoint_ring[wksu_breakpoint_head];
	memset(entry, 0, sizeof(*entry));
	entry->seq = wksu_breakpoint_next_seq++;
	entry->ts_ns = ktime_get_ns();
	entry->pid = task_pid_nr(current);
	entry->tgid = task_tgid_nr(current);
	entry->cpu = raw_smp_processor_id();
	entry->id = bp->id;
	entry->pc = pc;
	entry->far = far;
	entry->bp_addr = bp->addr;
	entry->pstate = pstate;
	entry->sp = sp;
	entry->lr = lr;
	entry->len = bp->len;
	entry->type = bp->type;
	entry->access_type = WKSU_BREAKPOINT_ACCESS_UNKNOWN;
	if (regs) {
		for (i = 0; i < ARRAY_SIZE(entry->regs); i++)
			entry->regs[i] = regs->regs[i];
	}

	wksu_breakpoint_head = (wksu_breakpoint_head + 1) %
			       WKSU_BREAKPOINT_RING_SIZE;
	if (wksu_breakpoint_count < WKSU_BREAKPOINT_RING_SIZE)
		wksu_breakpoint_count++;
	else {
		wksu_breakpoint_tail = (wksu_breakpoint_tail + 1) %
				       WKSU_BREAKPOINT_RING_SIZE;
		wksu_breakpoint_dropped++;
	}
	spin_unlock_irqrestore(&wksu_breakpoint_event_lock, flags);
	wake_up_interruptible(&wksu_breakpoint_wait);

	/*
	 * The breakpoint ring is the per-hit event source. Audit only records
	 * the first hit so a hot watchpoint cannot evict hook/mmap audit state.
	 */
	if (hits == 1)
		wksu_audit_log(WKSU_AUDIT_BREAKPOINT_HIT, 0, bp->addr, far,
			       pc, bp->name);
}

static void wksu_breakpoint_handler(struct perf_event *event,
				    struct perf_sample_data *data,
				    struct pt_regs *regs)
{
	struct wksu_breakpoint *bp = event->overflow_handler_context;

	wksu_breakpoint_push_event(bp, event, data, regs);
}

static int wksu_breakpoint_collect_tasks(s32 pid, u32 flags,
					 struct task_struct **tasks,
					 u32 *task_count, s32 *target_pid,
					 s32 *target_tgid)
{
	struct task_struct *task;
	struct task_struct *thread;
	u32 count = 0;
	int ret = 0;

	if (!tasks || !task_count || !target_pid || !target_tgid)
		return -EINVAL;

	read_lock(&tasklist_lock);
	task = find_task_by_vpid(pid);
	if (!task) {
		ret = -ESRCH;
		goto out;
	}

	if (flags & WKSU_BREAKPOINT_F_THREAD) {
		get_task_struct(task);
		tasks[count++] = task;
		*target_pid = task_pid_nr(task);
		*target_tgid = task_tgid_nr(task);
		goto out_count;
	}

	*target_pid = task_tgid_nr(task);
	*target_tgid = task_tgid_nr(task);
	for_each_thread(task->group_leader, thread) {
		if (count == WKSU_BREAKPOINT_MAX_TARGETS) {
			ret = -E2BIG;
			break;
		}
		get_task_struct(thread);
		tasks[count++] = thread;
	}

out_count:
	if (!count && !ret)
		ret = -ESRCH;
out:
	read_unlock(&tasklist_lock);

	if (ret) {
		while (count)
			put_task_struct(tasks[--count]);
		return ret;
	}

	*task_count = count;
	return 0;
}

static int wksu_breakpoint_register_event_array(struct wksu_breakpoint *bp,
						struct task_struct **tasks,
						u32 task_count,
						struct perf_event **events,
						pid_t *event_pids,
						u32 *event_count)
{
	struct perf_event_attr attr;
	u32 count = 0;
	u32 i;
	int ret;

#if !defined(CONFIG_HAVE_HW_BREAKPOINT) || !defined(CONFIG_PERF_EVENTS)
	return -EOPNOTSUPP;
#endif

	if (!bp || !tasks || !events || !event_pids || !event_count)
		return -EINVAL;

	*event_count = 0;
	hw_breakpoint_init(&attr);
	attr.bp_addr = bp->addr;
	attr.bp_len = bp->len;
	attr.bp_type = bp->type;
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.disabled = 1;

	for (i = 0; i < task_count; i++) {
		struct perf_event *event;

		event = register_user_hw_breakpoint(&attr,
						    wksu_breakpoint_handler,
						    bp, tasks[i]);
		if (IS_ERR(event)) {
			ret = PTR_ERR(event);
			goto out_unregister;
		}
		if (!event) {
			ret = -EOPNOTSUPP;
			goto out_unregister;
		}

		events[count] = event;
		event_pids[count] = task_pid_nr(tasks[i]);
		count++;
	}

	*event_count = count;
	return 0;

out_unregister:
	wksu_breakpoint_unregister_event_array(events, count);
	return ret;
}

static int wksu_breakpoint_add(s32 pid, u64 addr, u32 len, u32 type,
			       u32 flags, const char *name, u32 *id_out)
{
	struct task_struct **tasks;
	struct wksu_breakpoint *bp;
	struct perf_event *events[WKSU_BREAKPOINT_MAX_TARGETS] = { 0 };
	pid_t event_pids[WKSU_BREAKPOINT_MAX_TARGETS] = { 0 };
	u32 task_count = 0;
	u32 event_count = 0;
	s32 target_pid = 0;
	s32 target_tgid = 0;
	int ret;
	u32 i;

	if (pid <= 0 || !addr || !wksu_breakpoint_len_valid(len))
		return -EINVAL;
	if (flags & ~(WKSU_BREAKPOINT_F_THREAD | WKSU_BREAKPOINT_F_DISABLED))
		return -EINVAL;
	if (!wksu_breakpoint_type_valid(type))
		return -EINVAL;
	if (type != HW_BREAKPOINT_X && (addr & (len - 1)))
		return -EINVAL;
	if (addr > U64_MAX - len)
		return -EINVAL;

	tasks = kcalloc(WKSU_BREAKPOINT_MAX_TARGETS, sizeof(*tasks),
			GFP_KERNEL);
	if (!tasks)
		return -ENOMEM;

	ret = wksu_breakpoint_collect_tasks(pid, flags, tasks, &task_count,
					   &target_pid, &target_tgid);
	if (ret)
		goto out_tasks;

	mutex_lock(&wksu_breakpoint_lock);
	if (wksu_breakpoint_duplicate_locked(target_pid, target_tgid, addr,
					     len, type, flags)) {
		ret = -EEXIST;
		goto out_unlock;
	}

	bp = wksu_breakpoint_free_slot_locked();
	if (!bp) {
		ret = -ENOSPC;
		goto out_unlock;
	}

	memset(bp, 0, sizeof(*bp));
	bp->used = true;
	bp->enabled = !(flags & WKSU_BREAKPOINT_F_DISABLED);
	bp->id = wksu_breakpoint_alloc_id();
	bp->flags = flags;
	bp->len = len;
	bp->type = type;
	bp->requested_pid = (flags & WKSU_BREAKPOINT_F_THREAD) ?
			    pid : target_tgid;
	bp->target_pid = target_pid;
	bp->target_tgid = target_tgid;
	bp->addr = addr;
	atomic64_set(&bp->hits, 0);
	if (name && name[0])
		strscpy(bp->name, name, sizeof(bp->name));
	else
		strscpy(bp->name, "breakpoint", sizeof(bp->name));

	ret = wksu_breakpoint_register_event_array(bp, tasks, task_count,
						   events, event_pids,
						   &event_count);
	if (ret) {
		bp->last_error = ret;
		memset(bp, 0, sizeof(*bp));
		goto out_unlock;
	}
	memcpy(bp->events, events, event_count * sizeof(events[0]));
	memcpy(bp->event_pids, event_pids, event_count * sizeof(event_pids[0]));
	bp->event_count = event_count;
	if (bp->enabled)
		wksu_breakpoint_enable_event_array(bp->events, bp->event_count,
						   true);

	if (id_out)
		*id_out = bp->id;

out_unlock:
	mutex_unlock(&wksu_breakpoint_lock);
out_tasks:
	for (i = 0; i < task_count; i++)
		put_task_struct(tasks[i]);
	kfree(tasks);
	return ret;
}

static int wksu_breakpoint_remove(u32 id)
{
	struct wksu_breakpoint *bp;
	int ret = 0;

	if (!id)
		return -EINVAL;

	mutex_lock(&wksu_breakpoint_lock);
	bp = wksu_breakpoint_find_locked(id);
	if (!bp) {
		ret = -ENOENT;
		goto out;
	}

	wksu_breakpoint_unregister_locked(bp);
	memset(bp, 0, sizeof(*bp));
out:
	mutex_unlock(&wksu_breakpoint_lock);
	return ret;
}

static int wksu_breakpoint_enable(u32 id, bool enable)
{
	struct wksu_breakpoint *bp;
	u32 i;
	int ret = 0;

	if (!id)
		return -EINVAL;

	mutex_lock(&wksu_breakpoint_lock);
	bp = wksu_breakpoint_find_locked(id);
	if (!bp) {
		ret = -ENOENT;
		goto out;
	}

	for (i = 0; i < bp->event_count; i++) {
		if (!bp->events[i])
			continue;
		if (enable)
			perf_event_enable(bp->events[i]);
		else
			perf_event_disable(bp->events[i]);
	}
	bp->enabled = enable;
	bp->last_error = 0;
out:
	mutex_unlock(&wksu_breakpoint_lock);
	return ret;
}

static int wksu_breakpoint_refresh_one(u32 id)
{
	struct task_struct **tasks;
	struct task_struct **missing_tasks;
	struct wksu_breakpoint *bp;
	struct perf_event *events[WKSU_BREAKPOINT_MAX_TARGETS] = { 0 };
	struct perf_event *stale_events[WKSU_BREAKPOINT_MAX_TARGETS] = { 0 };
	pid_t event_pids[WKSU_BREAKPOINT_MAX_TARGETS] = { 0 };
	u32 task_count = 0;
	u32 missing_count = 0;
	u32 event_count = 0;
	u32 old_event_count;
	u32 stale_count = 0;
	u32 kept_count = 0;
	u32 i;
	s32 pid;
	u32 flags;
	s32 target_pid = 0;
	s32 target_tgid = 0;
	bool was_enabled;
	int ret;

	if (!id)
		return -EINVAL;

	tasks = kcalloc(WKSU_BREAKPOINT_MAX_TARGETS, sizeof(*tasks),
			GFP_KERNEL);
	if (!tasks)
		return -ENOMEM;

	missing_tasks = kcalloc(WKSU_BREAKPOINT_MAX_TARGETS,
				sizeof(*missing_tasks), GFP_KERNEL);
	if (!missing_tasks) {
		kfree(tasks);
		return -ENOMEM;
	}

	mutex_lock(&wksu_breakpoint_lock);
	bp = wksu_breakpoint_find_locked(id);
	if (!bp) {
		ret = -ENOENT;
		goto out_unlock_no_tasks;
	}
	flags = bp->flags;
	pid = (flags & WKSU_BREAKPOINT_F_THREAD) ?
	      bp->requested_pid : bp->target_tgid;
	was_enabled = bp->enabled;
	mutex_unlock(&wksu_breakpoint_lock);

	ret = wksu_breakpoint_collect_tasks(pid, flags, tasks, &task_count,
					    &target_pid, &target_tgid);
	if (ret)
		goto out_tasks;

	mutex_lock(&wksu_breakpoint_lock);
	bp = wksu_breakpoint_find_locked(id);
	if (!bp || bp->requested_pid != pid || bp->flags != flags ||
	    bp->enabled != was_enabled) {
		ret = -ENOENT;
		goto out_unlock;
	}

	for (i = 0; i < task_count; i++) {
		pid_t task_pid = task_pid_nr(tasks[i]);

		if (!wksu_breakpoint_has_event_pid(bp, task_pid))
			missing_tasks[missing_count++] = tasks[i];
	}

	ret = wksu_breakpoint_register_event_array(bp, missing_tasks,
						   missing_count,
						   events, event_pids,
						   &event_count);
	if (ret) {
		bp->last_error = ret;
		bp->enabled = was_enabled;
		goto out_unlock;
	}

	old_event_count = bp->event_count;
	for (i = 0; i < old_event_count; i++) {
		if (bp->events[i] &&
		    wksu_breakpoint_task_list_has_pid(tasks, task_count,
						     bp->event_pids[i])) {
			bp->events[kept_count] = bp->events[i];
			bp->event_pids[kept_count] = bp->event_pids[i];
			kept_count++;
		} else if (bp->events[i]) {
			stale_events[stale_count++] = bp->events[i];
		}
	}

	for (i = kept_count; i < old_event_count; i++) {
		bp->events[i] = NULL;
		bp->event_pids[i] = 0;
	}
	memcpy(&bp->events[kept_count], events,
	       event_count * sizeof(events[0]));
	memcpy(&bp->event_pids[kept_count], event_pids,
	       event_count * sizeof(event_pids[0]));
	bp->event_count = kept_count + event_count;
	bp->enabled = was_enabled;
	bp->target_pid = target_pid;
	bp->target_tgid = target_tgid;
	bp->last_error = 0;

	wksu_breakpoint_unregister_event_array(stale_events, stale_count);
	if (was_enabled)
		wksu_breakpoint_enable_event_array(events, event_count,
						   true);

out_unlock:
	mutex_unlock(&wksu_breakpoint_lock);
out_tasks:
	for (i = 0; i < task_count; i++)
		put_task_struct(tasks[i]);
	kfree(missing_tasks);
	kfree(tasks);
	return ret;

out_unlock_no_tasks:
	mutex_unlock(&wksu_breakpoint_lock);
	kfree(missing_tasks);
	kfree(tasks);
	return ret;
}

static int wksu_breakpoint_refresh(u32 id)
{
	u32 ids[WKSU_BREAKPOINT_MAX_SLOTS];
	u32 count = 0;
	u32 i;
	int ret = 0;

	if (id)
		return wksu_breakpoint_refresh_one(id);

	mutex_lock(&wksu_breakpoint_lock);
	for (i = 0; i < WKSU_BREAKPOINT_MAX_SLOTS; i++) {
		if (!wksu_breakpoints[i].used)
			continue;
		if (wksu_breakpoints[i].flags & WKSU_BREAKPOINT_F_THREAD)
			continue;
		ids[count++] = wksu_breakpoints[i].id;
	}
	mutex_unlock(&wksu_breakpoint_lock);

	for (i = 0; i < count; i++) {
		int cur = wksu_breakpoint_refresh_one(ids[i]);

		if (cur && !ret)
			ret = cur;
	}

	return ret;
}

static void wksu_breakpoint_list(struct wksu_breakpoint_info *infos,
				 u32 max_infos, u32 *info_count)
{
	u32 copied = 0;
	int i;

	mutex_lock(&wksu_breakpoint_lock);
	for (i = 0; i < WKSU_BREAKPOINT_MAX_SLOTS && copied < max_infos; i++) {
		if (!wksu_breakpoints[i].used)
			continue;
		wksu_breakpoint_fill_info(&wksu_breakpoints[i],
					  &infos[copied++]);
	}
	mutex_unlock(&wksu_breakpoint_lock);

	if (info_count)
		*info_count = copied;
}

static u32 wksu_breakpoint_total_locked(void)
{
	u32 total = 0;
	int i;

	for (i = 0; i < WKSU_BREAKPOINT_MAX_SLOTS; i++) {
		if (wksu_breakpoints[i].used)
			total++;
	}

	return total;
}

static void wksu_breakpoint_get_status(u32 *breakpoint_count,
				       u32 *event_count, u64 *dropped,
				       u64 *next_seq)
{
	unsigned long flags;

	mutex_lock(&wksu_breakpoint_lock);
	if (breakpoint_count)
		*breakpoint_count = wksu_breakpoint_total_locked();
	mutex_unlock(&wksu_breakpoint_lock);

	spin_lock_irqsave(&wksu_breakpoint_event_lock, flags);
	if (event_count)
		*event_count = wksu_breakpoint_count;
	if (dropped)
		*dropped = wksu_breakpoint_dropped;
	if (next_seq)
		*next_seq = wksu_breakpoint_next_seq;
	spin_unlock_irqrestore(&wksu_breakpoint_event_lock, flags);
}

static void wksu_breakpoint_read_events(struct wksu_breakpoint_event *events,
					u32 max_events, u32 *event_count,
					u64 *dropped, u64 *next_seq)
{
	u32 available;
	u32 count;
	u32 i;
	unsigned long flags;

	spin_lock_irqsave(&wksu_breakpoint_event_lock, flags);
	available = wksu_breakpoint_count;
	count = min(max_events, available);
	if (!events)
		count = 0;

	for (i = 0; i < count; i++)
		events[i] = wksu_breakpoint_ring[(wksu_breakpoint_tail + i) %
						 WKSU_BREAKPOINT_RING_SIZE];

	wksu_breakpoint_tail = (wksu_breakpoint_tail + count) %
			       WKSU_BREAKPOINT_RING_SIZE;
	wksu_breakpoint_count -= count;

	if (event_count)
		*event_count = count;
	if (dropped)
		*dropped = wksu_breakpoint_dropped;
	if (next_seq)
		*next_seq = wksu_breakpoint_next_seq;
	spin_unlock_irqrestore(&wksu_breakpoint_event_lock, flags);
}

static bool wksu_breakpoint_events_available(void)
{
	return READ_ONCE(wksu_breakpoint_count) > 0;
}

static int wksu_breakpoint_wait_events(struct wksu_breakpoint_event *events,
				       u32 max_events, u32 timeout_ms,
				       u32 *event_count, u64 *dropped,
				       u64 *next_seq)
{
	long wait_result;

	if (timeout_ms > WKSU_BREAKPOINT_MAX_WAIT_MS)
		timeout_ms = WKSU_BREAKPOINT_MAX_WAIT_MS;

	if (!wksu_breakpoint_events_available() && timeout_ms) {
		wait_result = wait_event_interruptible_timeout(
			wksu_breakpoint_wait,
			wksu_breakpoint_events_available(),
			msecs_to_jiffies(timeout_ms));
		if (wait_result < 0)
			return wait_result;
	}

	wksu_breakpoint_read_events(events, max_events, event_count, dropped,
				    next_seq);
	return 0;
}

static void wksu_breakpoint_clear_events(void)
{
	unsigned long flags;

	spin_lock_irqsave(&wksu_breakpoint_event_lock, flags);
	wksu_breakpoint_head = 0;
	wksu_breakpoint_tail = 0;
	wksu_breakpoint_count = 0;
	wksu_breakpoint_next_seq = 0;
	wksu_breakpoint_dropped = 0;
	spin_unlock_irqrestore(&wksu_breakpoint_event_lock, flags);
	wake_up_interruptible(&wksu_breakpoint_wait);
}

void wksu_breakpoint_clear_all(void)
{
	int i;

	mutex_lock(&wksu_breakpoint_lock);
	for (i = 0; i < WKSU_BREAKPOINT_MAX_SLOTS; i++) {
		if (!wksu_breakpoints[i].used)
			continue;
		wksu_breakpoint_unregister_locked(&wksu_breakpoints[i]);
		memset(&wksu_breakpoints[i], 0, sizeof(wksu_breakpoints[i]));
	}
	mutex_unlock(&wksu_breakpoint_lock);

	wksu_breakpoint_clear_events();
}

int wksu_breakpoint_ioctl(void __user *arg)
{
	struct ksu_breakpoint_cmd *cmd;
	char name[WKSU_BREAKPOINT_NAME_LEN];
	u32 op;
	u32 id;
	u32 flags;
	u32 len;
	u32 type;
	u32 enabled;
	u32 timeout_ms;
	u32 max_events;
	u32 max_breakpoints;
	s32 pid;
	u64 addr;
	int ret = 0;

	cmd = kvzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	if (copy_from_user(cmd, arg, sizeof(*cmd))) {
		ret = -EFAULT;
		goto out;
	}

	op = cmd->op;
	id = cmd->id;
	pid = cmd->pid;
	flags = cmd->flags;
	addr = cmd->addr;
	len = cmd->len;
	type = cmd->type;
	enabled = cmd->enabled;
	timeout_ms = cmd->timeout_ms;
	max_events = min_t(u32, cmd->max_events, WKSU_BREAKPOINT_MAX_EVENTS);
	max_breakpoints = min_t(u32, cmd->max_breakpoints,
				WKSU_BREAKPOINT_MAX_INFOS);
	strscpy(name, cmd->name, sizeof(name));

	memset(cmd, 0, sizeof(*cmd));
	cmd->op = op;
	cmd->id = id;
	cmd->pid = pid;
	cmd->flags = flags;
	cmd->addr = addr;
	cmd->len = len;
	cmd->type = type;
	cmd->enabled = enabled;
	cmd->timeout_ms = min_t(u32, timeout_ms, WKSU_BREAKPOINT_MAX_WAIT_MS);
	cmd->max_events = max_events;
	cmd->max_breakpoints = max_breakpoints;
	strscpy(cmd->name, name, sizeof(cmd->name));

	if (wksu_breakpoint_op_mutates(op) &&
	    !wksu_is_pid_hidden(task_tgid_vnr(current))) {
		ret = -EACCES;
		goto copy_out;
	}

	switch (op) {
	case WKSU_BREAKPOINT_GET:
		wksu_breakpoint_get_status(&cmd->breakpoint_count,
					   &cmd->event_count, &cmd->dropped,
					   &cmd->next_seq);
		break;
	case WKSU_BREAKPOINT_ADD:
		ret = wksu_breakpoint_add(pid, addr, len, type, flags, name,
					  &cmd->id);
		break;
	case WKSU_BREAKPOINT_REMOVE:
		ret = wksu_breakpoint_remove(id);
		break;
	case WKSU_BREAKPOINT_LIST:
		wksu_breakpoint_list(cmd->breakpoints, max_breakpoints,
				     &cmd->breakpoint_count);
		break;
	case WKSU_BREAKPOINT_READ:
		wksu_breakpoint_read_events(cmd->events, max_events,
					    &cmd->event_count, &cmd->dropped,
					    &cmd->next_seq);
		break;
	case WKSU_BREAKPOINT_CLEAR:
		wksu_breakpoint_clear_events();
		break;
	case WKSU_BREAKPOINT_ENABLE:
		ret = wksu_breakpoint_enable(id, !!enabled);
		break;
	case WKSU_BREAKPOINT_REFRESH:
		ret = wksu_breakpoint_refresh(id);
		break;
	case WKSU_BREAKPOINT_WAIT:
		ret = wksu_breakpoint_wait_events(cmd->events, max_events,
						  cmd->timeout_ms,
						  &cmd->event_count,
						  &cmd->dropped,
						  &cmd->next_seq);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (op != WKSU_BREAKPOINT_LIST && op != WKSU_BREAKPOINT_READ &&
	    op != WKSU_BREAKPOINT_WAIT)
		wksu_breakpoint_get_status(&cmd->breakpoint_count,
					   &cmd->event_count, &cmd->dropped,
					   &cmd->next_seq);

copy_out:
	cmd->result = ret;
	if (copy_to_user(arg, cmd, sizeof(*cmd)))
		ret = -EFAULT;
out:
	kvfree(cmd);
	return ret;
}
