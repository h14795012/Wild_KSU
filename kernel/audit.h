#ifndef _WKSU_AUDIT_H
#define _WKSU_AUDIT_H

#include <linux/types.h>

#define WKSU_AUDIT_NAME_LEN 32
#define WKSU_AUDIT_MAX_EVENTS 64

#define WKSU_AUDIT_GET   0
#define WKSU_AUDIT_SET   1
#define WKSU_AUDIT_READ  2
#define WKSU_AUDIT_CLEAR 3

enum wksu_audit_type {
	WKSU_AUDIT_HOOK_INSTALL = 1,
	WKSU_AUDIT_HOOK_UNINSTALL,
	WKSU_AUDIT_HOOK_INSTALL_FAIL,
	WKSU_AUDIT_HOOK_UNINSTALL_FAIL,
	WKSU_AUDIT_HOOK_ENTRY_CHANGED,
	WKSU_AUDIT_MMAP_REMOTE_CREATE,
	WKSU_AUDIT_MMAP_REMOTE_RELEASE,
	WKSU_AUDIT_BREAKPOINT_HIT,
};

struct wksu_audit_event {
	__u64 seq;
	__u64 ts_ns;
	__s32 pid;
	__s32 tgid;
	__u32 cpu;
	__u32 type;
	__s32 result;
	__u32 _pad;
	__u64 addr0;
	__u64 addr1;
	__u64 addr2;
	char name[WKSU_AUDIT_NAME_LEN];
};

struct ksu_audit_cmd {
	__u32 op;
	__u32 enabled;
	__u32 max_events;
	__u32 event_count;
	__u64 dropped;
	__u64 next_seq;
	struct wksu_audit_event events[WKSU_AUDIT_MAX_EVENTS];
};

void wksu_audit_log(u32 type, int result, u64 addr0, u64 addr1, u64 addr2,
		    const char *name);
void wksu_audit_set_enabled(bool enabled);
bool wksu_audit_get_enabled(void);
void wksu_audit_clear(void);
void wksu_audit_snapshot(struct wksu_audit_event *events, u32 max_events,
			 u32 *event_count, u64 *dropped, u64 *next_seq,
			 bool *enabled);

#endif
