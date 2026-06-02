#include <linux/ktime.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "audit.h"

#define WKSU_AUDIT_RING_SIZE 256

static DEFINE_SPINLOCK(wksu_audit_lock);
static struct wksu_audit_event wksu_audit_ring[WKSU_AUDIT_RING_SIZE];
static u32 wksu_audit_head;
static u32 wksu_audit_count;
static u64 wksu_audit_next_seq;
static u64 wksu_audit_dropped;
static bool wksu_audit_enabled;

void wksu_audit_set_enabled(bool enabled)
{
	unsigned long flags;

	spin_lock_irqsave(&wksu_audit_lock, flags);
	wksu_audit_enabled = enabled;
	spin_unlock_irqrestore(&wksu_audit_lock, flags);
}

bool wksu_audit_get_enabled(void)
{
	bool enabled;
	unsigned long flags;

	spin_lock_irqsave(&wksu_audit_lock, flags);
	enabled = wksu_audit_enabled;
	spin_unlock_irqrestore(&wksu_audit_lock, flags);
	return enabled;
}

void wksu_audit_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&wksu_audit_lock, flags);
	wksu_audit_head = 0;
	wksu_audit_count = 0;
	wksu_audit_next_seq = 0;
	wksu_audit_dropped = 0;
	spin_unlock_irqrestore(&wksu_audit_lock, flags);
}

void wksu_audit_log(u32 type, int result, u64 addr0, u64 addr1, u64 addr2,
		    const char *name)
{
	struct wksu_audit_event *event;
	unsigned long flags;

	spin_lock_irqsave(&wksu_audit_lock, flags);
	if (!wksu_audit_enabled) {
		spin_unlock_irqrestore(&wksu_audit_lock, flags);
		return;
	}

	event = &wksu_audit_ring[wksu_audit_head];
	memset(event, 0, sizeof(*event));
	event->seq = wksu_audit_next_seq++;
	event->ts_ns = ktime_get_ns();
	event->pid = task_pid_nr(current);
	event->tgid = task_tgid_nr(current);
	event->cpu = raw_smp_processor_id();
	event->type = type;
	event->result = result;
	event->addr0 = addr0;
	event->addr1 = addr1;
	event->addr2 = addr2;
	if (name)
		strscpy(event->name, name, sizeof(event->name));

	wksu_audit_head = (wksu_audit_head + 1) % WKSU_AUDIT_RING_SIZE;
	if (wksu_audit_count < WKSU_AUDIT_RING_SIZE)
		wksu_audit_count++;
	else
		wksu_audit_dropped++;

	spin_unlock_irqrestore(&wksu_audit_lock, flags);
}

void wksu_audit_snapshot(struct wksu_audit_event *events, u32 max_events,
			 u32 *event_count, u64 *dropped, u64 *next_seq,
			 bool *enabled)
{
	u32 available;
	u32 start;
	u32 count;
	u32 copied;
	u32 i;
	unsigned long flags;

	spin_lock_irqsave(&wksu_audit_lock, flags);
	available = wksu_audit_count;
	count = min(max_events, available);
	if (!events)
		count = 0;
	copied = count;
	start = (wksu_audit_head + WKSU_AUDIT_RING_SIZE - available) %
		WKSU_AUDIT_RING_SIZE;
	start = (start + available - count) % WKSU_AUDIT_RING_SIZE;

	for (i = 0; i < count; i++)
		events[i] = wksu_audit_ring[(start + i) %
					    WKSU_AUDIT_RING_SIZE];

	if (event_count)
		*event_count = events ? copied : available;
	if (dropped)
		*dropped = wksu_audit_dropped;
	if (next_seq)
		*next_seq = wksu_audit_next_seq;
	if (enabled)
		*enabled = wksu_audit_enabled;
	spin_unlock_irqrestore(&wksu_audit_lock, flags);
}
