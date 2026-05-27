#ifndef _WKSU_HOOK_H
#define _WKSU_HOOK_H

#include <linux/types.h>

struct wksu_hook {
	void *target;
	void *replacement;
	void *trampoline;
	u32 orig_insn;
	bool installed;
};

int wksu_hook_install(struct wksu_hook *hook);
void wksu_hook_uninstall(struct wksu_hook *hook);

#endif
