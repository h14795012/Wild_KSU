#ifndef _WKSU_HOOK_H
#define _WKSU_HOOK_H

#include <linux/types.h>

#define WKSU_HOOK_NAME_LEN 32
#define WKSU_HOOK_MAX_STATUS 64

struct wksu_hook {
	void *target;
	void *replacement;
	void *trampoline;
	u32 orig_insn;
	u32 branch_insn;
	u32 checksum;
	int last_error;
	bool installed;
	bool entry_changed_reported;
	char name[WKSU_HOOK_NAME_LEN];
};

struct wksu_hook_info {
	__u64 target;
	__u64 replacement;
	__u64 trampoline;
	__u32 orig_insn;
	__u32 branch_insn;
	__u32 current_insn;
	__u32 checksum;
	__s32 last_error;
	__u32 installed;
	__u32 entry_changed;
	char name[WKSU_HOOK_NAME_LEN];
};

struct ksu_hook_status_cmd {
	__u32 max_hooks;
	__u32 hook_count;
	__u32 total_hooks;
	__u32 _pad;
	struct wksu_hook_info hooks[WKSU_HOOK_MAX_STATUS];
};

int wksu_hook_install(struct wksu_hook *hook);
void wksu_hook_uninstall(struct wksu_hook *hook);
void wksu_hook_snapshot(struct wksu_hook_info *infos, u32 max_hooks,
			u32 *hook_count, u32 *total_hooks);
void wksu_hook_clear_all(void);

#endif
