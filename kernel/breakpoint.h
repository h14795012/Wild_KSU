#ifndef _WKSU_BREAKPOINT_H
#define _WKSU_BREAKPOINT_H

#include <linux/types.h>

#define WKSU_BREAKPOINT_NAME_LEN 32
#define WKSU_BREAKPOINT_MAX_EVENTS 64
#define WKSU_BREAKPOINT_MAX_INFOS 16

#define WKSU_BREAKPOINT_GET    0
#define WKSU_BREAKPOINT_ADD    1
#define WKSU_BREAKPOINT_REMOVE 2
#define WKSU_BREAKPOINT_LIST   3
#define WKSU_BREAKPOINT_READ   4
#define WKSU_BREAKPOINT_CLEAR  5
#define WKSU_BREAKPOINT_ENABLE 6
#define WKSU_BREAKPOINT_REFRESH 7
#define WKSU_BREAKPOINT_WAIT   8

#define WKSU_BREAKPOINT_F_THREAD   (1U << 0)
#define WKSU_BREAKPOINT_F_DISABLED (1U << 1)

#define WKSU_BREAKPOINT_ACCESS_UNKNOWN 0

struct wksu_breakpoint_event {
	__u64 seq;
	__u64 ts_ns;
	__s32 pid;
	__s32 tgid;
	__u32 cpu;
	__u32 id;
	__u64 pc;
	__u64 far;
	__u64 bp_addr;
	__u64 pstate;
	__u64 sp;
	__u64 lr;
	__u64 regs[8];
	__u32 len;
	__u32 type;
	/* Actual read/write direction is not decoded in the generic callback. */
	__u32 access_type;
	__u32 _pad;
};

struct wksu_breakpoint_info {
	__u32 id;
	__u32 flags;
	__s32 pid;
	__s32 tgid;
	__u64 addr;
	__u32 len;
	__u32 type;
	__u32 task_count;
	__u32 enabled;
	__s32 last_error;
	__u64 hits;
	char name[WKSU_BREAKPOINT_NAME_LEN];
};

struct ksu_breakpoint_cmd {
	__u32 op;
	__u32 id;
	__s32 pid;
	__u32 flags;
	__u64 addr;
	__u32 len;
	__u32 type;
	__u32 enabled;
	__u32 max_events;
	__u32 event_count;
	__u32 max_breakpoints;
	__u32 breakpoint_count;
	__u64 dropped;
	__u64 next_seq;
	__s32 result;
	__u32 timeout_ms;
	char name[WKSU_BREAKPOINT_NAME_LEN];
	struct wksu_breakpoint_info breakpoints[WKSU_BREAKPOINT_MAX_INFOS];
	struct wksu_breakpoint_event events[WKSU_BREAKPOINT_MAX_EVENTS];
};

int wksu_breakpoint_ioctl(void __user *arg);
void wksu_breakpoint_clear_all(void);

#endif
