#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/moduleloader.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/debug-monitors.h>
#include <asm/insn.h>
#include <asm/memory.h>
#include <asm/module.h>
#include <asm/sections.h>

#include "audit.h"
#include "hook.h"

static DEFINE_MUTEX(wksu_hook_mutex);

#define WKSU_TRAMPOLINE_INSN_COUNT 5
#define WKSU_HOOK_REGISTRY_SIZE 64

static struct wksu_hook *wksu_hook_registry[WKSU_HOOK_REGISTRY_SIZE];

struct wksu_trampoline_free {
	struct rcu_head rcu;
	void *addr;
};

static bool wksu_hook_addr_aligned(const void *addr)
{
	return !((unsigned long)addr & (sizeof(u32) - 1));
}

static bool wksu_branch_reachable(unsigned long pc, unsigned long addr)
{
	long offset = (long)addr - (long)pc;

	return offset >= -SZ_128M && offset < SZ_128M;
}

static int wksu_patch_text(void *addr, u32 insn)
{
	void *addrs[1] = { addr };
	u32 insns[1] = { insn };

	return aarch64_insn_patch_text(addrs, insns, 1);
}

static bool wksu_hook_entry_busy(u32 insn)
{
	return aarch64_insn_is_branch(insn) ||
	       aarch64_insn_uses_literal(insn);
}

static u32 wksu_hook_checksum(struct wksu_hook *hook)
{
	unsigned long target = (unsigned long)hook->target;
	unsigned long replacement = (unsigned long)hook->replacement;
	unsigned long trampoline = (unsigned long)hook->trampoline;

	return hook->orig_insn ^ hook->branch_insn ^
	       (u32)target ^ (u32)(target >> 32) ^
	       (u32)replacement ^ (u32)(replacement >> 32) ^
	       (u32)trampoline ^ (u32)(trampoline >> 32);
}

static const char *wksu_hook_name(struct wksu_hook *hook)
{
	if (!hook || !hook->name[0])
		return "hook";

	return hook->name;
}

static int wksu_hook_registry_find(struct wksu_hook *hook)
{
	int i;

	for (i = 0; i < WKSU_HOOK_REGISTRY_SIZE; i++) {
		if (wksu_hook_registry[i] == hook)
			return i;
	}

	return -ENOENT;
}

static struct wksu_hook *wksu_hook_registry_find_target(void *target)
{
	int i;

	for (i = 0; i < WKSU_HOOK_REGISTRY_SIZE; i++) {
		if (wksu_hook_registry[i] &&
		    wksu_hook_registry[i]->target == target)
			return wksu_hook_registry[i];
	}

	return NULL;
}

static int wksu_hook_registry_add(struct wksu_hook *hook)
{
	int i;

	if (wksu_hook_registry_find(hook) >= 0)
		return 0;

	for (i = 0; i < WKSU_HOOK_REGISTRY_SIZE; i++) {
		if (!wksu_hook_registry[i]) {
			wksu_hook_registry[i] = hook;
			return 0;
		}
	}

	return -ENOSPC;
}

static void wksu_hook_registry_remove(struct wksu_hook *hook)
{
	int i;

	i = wksu_hook_registry_find(hook);
	if (i >= 0)
		wksu_hook_registry[i] = NULL;
}

static void wksu_free_trampoline_now(void *addr)
{
	if (!addr)
		return;

	/*
	 * vfree() removes the vmalloc area through remove_vm_area(), which
	 * releases KASAN module shadow via kasan_free_shadow() when needed.
	 */
	vfree(addr);
}

static void wksu_free_trampoline_rcu(struct rcu_head *rcu)
{
	struct wksu_trampoline_free *free;

	free = container_of(rcu, struct wksu_trampoline_free, rcu);
	wksu_free_trampoline_now(free->addr);
	kfree(free);
}

static void wksu_queue_trampoline_free(void *addr)
{
	struct wksu_trampoline_free *free;

	if (!addr)
		return;

	free = kmalloc(sizeof(*free), GFP_KERNEL);
	if (!free) {
		pr_warn_once("wksu: leaking trampoline at %px\n", addr);
		return;
	}

	free->addr = addr;
	call_rcu_tasks(&free->rcu, wksu_free_trampoline_rcu);
}

static void *wksu_alloc_trampoline_near(void *target)
{
	unsigned long pc = (unsigned long)target;
	unsigned long range_start = pc > SZ_128M ? pc - SZ_128M : 0;
	unsigned long range_end = pc + SZ_128M;
	unsigned long start;
	unsigned long end;
	void *trampoline;

	if (range_end < pc)
		range_end = ~0UL;

	start = max_t(unsigned long, module_alloc_base, range_start);
	end = min_t(unsigned long, module_alloc_base + MODULES_VSIZE,
		    MODULES_END);
	end = min_t(unsigned long, end, range_end);
	if (start >= end)
		return NULL;

	trampoline = __vmalloc_node_range(PAGE_SIZE, MODULE_ALIGN, start, end,
					  GFP_KERNEL, PAGE_KERNEL,
					  VM_FLUSH_RESET_PERMS, NUMA_NO_NODE,
					  __builtin_return_address(0));
	if (trampoline && kasan_module_alloc(trampoline, PAGE_SIZE) < 0) {
		wksu_free_trampoline_now(trampoline);
		return NULL;
	}

	return trampoline;
}

static int wksu_emit_trampoline(void *trampoline, void *replacement)
{
	unsigned long addr = (unsigned long)replacement;
	enum aarch64_insn_register reg = AARCH64_INSN_REG_16;
	u32 insns[WKSU_TRAMPOLINE_INSN_COUNT];
	int i;
	int ret;

	insns[0] = aarch64_insn_gen_movewide(reg, addr & 0xffff, 0,
					      AARCH64_INSN_VARIANT_64BIT,
					      AARCH64_INSN_MOVEWIDE_ZERO);
	insns[1] = aarch64_insn_gen_movewide(reg, (addr >> 16) & 0xffff, 16,
					      AARCH64_INSN_VARIANT_64BIT,
					      AARCH64_INSN_MOVEWIDE_KEEP);
	insns[2] = aarch64_insn_gen_movewide(reg, (addr >> 32) & 0xffff, 32,
					      AARCH64_INSN_VARIANT_64BIT,
					      AARCH64_INSN_MOVEWIDE_KEEP);
	insns[3] = aarch64_insn_gen_movewide(reg, (addr >> 48) & 0xffff, 48,
					      AARCH64_INSN_VARIANT_64BIT,
					      AARCH64_INSN_MOVEWIDE_KEEP);
	/*
	 * This indirect branch requires replacement to be a valid indirect
	 * branch landing target on BTI-enabled kernels.
	 */
	insns[4] = aarch64_insn_gen_branch_reg(reg,
						AARCH64_INSN_BRANCH_NOLINK);

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		if (insns[i] == AARCH64_BREAK_FAULT)
			return -EINVAL;

		ret = aarch64_insn_patch_text_nosync(
			(void *)((unsigned long)trampoline + i * sizeof(u32)),
			insns[i]);
		if (ret)
			return ret;
	}

	ret = set_memory_x((unsigned long)trampoline, 1);
	if (ret)
		return ret;

	return set_memory_ro((unsigned long)trampoline, 1);
}

static int wksu_prepare_branch(struct wksu_hook *hook, u32 *branch)
{
	void *trampoline;
	int ret;

	*branch = aarch64_insn_gen_branch_imm((unsigned long)hook->target,
					      (unsigned long)hook->replacement,
					      AARCH64_INSN_BRANCH_NOLINK);
	if (*branch != AARCH64_BREAK_FAULT)
		return 0;

	trampoline = wksu_alloc_trampoline_near(hook->target);
	if (!trampoline)
		return -ERANGE;

	if (!wksu_branch_reachable((unsigned long)hook->target,
				   (unsigned long)trampoline)) {
		ret = -ERANGE;
		goto free_trampoline;
	}

	ret = wksu_emit_trampoline(trampoline, hook->replacement);
	if (ret)
		goto free_trampoline;

	*branch = aarch64_insn_gen_branch_imm((unsigned long)hook->target,
					      (unsigned long)trampoline,
					      AARCH64_INSN_BRANCH_NOLINK);
	if (*branch == AARCH64_BREAK_FAULT) {
		ret = -ERANGE;
		goto free_trampoline;
	}

	hook->trampoline = trampoline;
	return 0;

free_trampoline:
	wksu_free_trampoline_now(trampoline);
	return ret;
}

int wksu_hook_install(struct wksu_hook *hook)
{
	struct wksu_hook *existing;
	u32 branch;
	u32 current_insn;
	u32 orig;
	bool read_failed;
	int rollback_ret;
	int ret = 0;

	if (!hook || !hook->target || !hook->replacement) {
		wksu_audit_log(WKSU_AUDIT_HOOK_INSTALL_FAIL, -EINVAL, 0, 0, 0,
			       NULL);
		return -EINVAL;
	}

	if (!wksu_hook_addr_aligned(hook->target) ||
	    !wksu_hook_addr_aligned(hook->replacement)) {
		wksu_audit_log(WKSU_AUDIT_HOOK_INSTALL_FAIL, -EINVAL,
			       (u64)hook->target, (u64)hook->replacement, 0,
			       wksu_hook_name(hook));
		return -EINVAL;
	}

	mutex_lock(&wksu_hook_mutex);
	hook->last_error = 0;

	if (hook->installed) {
		ret = aarch64_insn_read(hook->target, &current_insn);
		if (ret || current_insn != hook->branch_insn) {
			hook->last_error = ret ? ret : -EBUSY;
			hook->entry_changed_reported = true;
			wksu_audit_log(WKSU_AUDIT_HOOK_ENTRY_CHANGED,
				       hook->last_error, (u64)hook->target,
				       hook->branch_insn,
				       ret ? 0 : current_insn,
				       wksu_hook_name(hook));
			ret = hook->last_error;
		}
		goto out;
	}

	existing = wksu_hook_registry_find_target(hook->target);
	if (existing && existing != hook) {
		ret = -EBUSY;
		goto fail;
	}

	ret = aarch64_insn_read(hook->target, &orig);
	if (ret)
		goto fail;

	if (wksu_hook_entry_busy(orig)) {
		ret = -EBUSY;
		goto fail;
	}

	hook->trampoline = NULL;
	ret = wksu_prepare_branch(hook, &branch);
	if (ret)
		goto fail;

	hook->orig_insn = orig;
	hook->branch_insn = branch;
	hook->checksum = wksu_hook_checksum(hook);
	ret = wksu_hook_registry_add(hook);
	if (ret) {
		wksu_queue_trampoline_free(hook->trampoline);
		hook->trampoline = NULL;
		goto fail;
	}

	ret = aarch64_insn_read(hook->target, &current_insn);
	if (ret || current_insn != orig) {
		ret = ret ? ret : -EBUSY;
		hook->last_error = ret;
		hook->entry_changed_reported = true;
		wksu_audit_log(WKSU_AUDIT_HOOK_ENTRY_CHANGED, ret,
			       (u64)hook->target, orig,
			       ret ? 0 : current_insn,
			       wksu_hook_name(hook));
		wksu_hook_registry_remove(hook);
		wksu_queue_trampoline_free(hook->trampoline);
		hook->trampoline = NULL;
		goto fail;
	}

	ret = wksu_patch_text(hook->target, branch);
	if (ret) {
		wksu_hook_registry_remove(hook);
		wksu_queue_trampoline_free(hook->trampoline);
		hook->trampoline = NULL;
		goto fail;
	}

	ret = aarch64_insn_read(hook->target, &current_insn);
	read_failed = ret;
	if (read_failed || current_insn != branch) {
		ret = ret ? ret : -EIO;
		rollback_ret = wksu_patch_text(hook->target, orig);
		if (rollback_ret) {
			hook->installed = true;
			hook->last_error = rollback_ret;
			hook->entry_changed_reported = true;
			ret = rollback_ret;
			wksu_audit_log(WKSU_AUDIT_HOOK_ENTRY_CHANGED,
				       rollback_ret, (u64)hook->target,
				       branch, read_failed ? 0 : current_insn,
				       wksu_hook_name(hook));
			WARN_ONCE(1, "wksu: failed to roll back hook at %ps\n",
				  hook->target);
		} else {
			wksu_hook_registry_remove(hook);
			wksu_queue_trampoline_free(hook->trampoline);
			hook->trampoline = NULL;
		}
		goto fail;
	}

	hook->installed = true;
	hook->entry_changed_reported = false;
	wksu_audit_log(WKSU_AUDIT_HOOK_INSTALL, 0, (u64)hook->target,
		       (u64)hook->replacement, (u64)hook->trampoline,
		       wksu_hook_name(hook));
	goto out;

fail:
	if (!hook->last_error)
		hook->last_error = ret;
	wksu_audit_log(WKSU_AUDIT_HOOK_INSTALL_FAIL, ret,
		       (u64)hook->target, (u64)hook->replacement,
		       (u64)hook->trampoline, wksu_hook_name(hook));

out:
	mutex_unlock(&wksu_hook_mutex);
	return ret;
}

void wksu_hook_uninstall(struct wksu_hook *hook)
{
	u32 current_insn;
	int ret;

	if (!hook || !hook->target)
		return;

	mutex_lock(&wksu_hook_mutex);

	if (!hook->installed)
		goto out;

	ret = aarch64_insn_read(hook->target, &current_insn);
	if (ret || current_insn != hook->branch_insn) {
		hook->last_error = ret ? ret : -EBUSY;
		hook->entry_changed_reported = true;
		wksu_audit_log(WKSU_AUDIT_HOOK_ENTRY_CHANGED,
			       hook->last_error, (u64)hook->target,
			       hook->branch_insn, ret ? 0 : current_insn,
			       wksu_hook_name(hook));
		wksu_audit_log(WKSU_AUDIT_HOOK_UNINSTALL_FAIL,
			       hook->last_error, (u64)hook->target,
			       (u64)hook->replacement, (u64)hook->trampoline,
			       wksu_hook_name(hook));
		goto out;
	}

	/*
	 * Restoring target is stop_machine-synchronized by patch_text().
	 * If a CPU was interrupted while executing the trampoline, the target
	 * no longer admits new entrants after this point, and trampoline memory
	 * is released after an RCU-tasks grace period instead of immediately.
	 */
	ret = wksu_patch_text(hook->target, hook->orig_insn);
	if (ret) {
		hook->last_error = ret;
		wksu_audit_log(WKSU_AUDIT_HOOK_UNINSTALL_FAIL, ret,
			       (u64)hook->target, (u64)hook->replacement,
			       (u64)hook->trampoline, wksu_hook_name(hook));
		WARN_ONCE(1, "wksu: failed to uninstall hook at %ps: %d\n",
			  hook->target, ret);
	} else {
		wksu_queue_trampoline_free(hook->trampoline);
		hook->trampoline = NULL;
		hook->installed = false;
		hook->last_error = 0;
		hook->entry_changed_reported = false;
		wksu_hook_registry_remove(hook);
		wksu_audit_log(WKSU_AUDIT_HOOK_UNINSTALL, 0,
			       (u64)hook->target, (u64)hook->replacement, 0,
			       wksu_hook_name(hook));
	}

out:
	mutex_unlock(&wksu_hook_mutex);
}

void wksu_hook_snapshot(struct wksu_hook_info *infos, u32 max_hooks,
			u32 *hook_count, u32 *total_hooks)
{
	struct wksu_hook *hook;
	u32 current_insn;
	u32 copied = 0;
	u32 total = 0;
	int ret;
	int i;

	if (max_hooks > WKSU_HOOK_MAX_STATUS)
		max_hooks = WKSU_HOOK_MAX_STATUS;

	mutex_lock(&wksu_hook_mutex);
	for (i = 0; i < WKSU_HOOK_REGISTRY_SIZE; i++) {
		hook = wksu_hook_registry[i];
		if (!hook)
			continue;

		total++;
		ret = aarch64_insn_read(hook->target, &current_insn);
		if (ret)
			current_insn = 0;

		if (hook->installed &&
		    (ret || current_insn != hook->branch_insn)) {
			hook->last_error = ret ? ret : -EBUSY;
			if (!hook->entry_changed_reported) {
				wksu_audit_log(WKSU_AUDIT_HOOK_ENTRY_CHANGED,
					       hook->last_error,
					       (u64)hook->target,
					       hook->branch_insn,
					       ret ? 0 : current_insn,
					       wksu_hook_name(hook));
				hook->entry_changed_reported = true;
			}
		} else {
			hook->entry_changed_reported = false;
			if (hook->installed)
				hook->last_error = 0;
		}

		if (copied < max_hooks && infos) {
			memset(&infos[copied], 0, sizeof(infos[copied]));
			infos[copied].target = (u64)hook->target;
			infos[copied].replacement = (u64)hook->replacement;
			infos[copied].trampoline = (u64)hook->trampoline;
			infos[copied].orig_insn = hook->orig_insn;
			infos[copied].branch_insn = hook->branch_insn;
			infos[copied].current_insn = current_insn;
			infos[copied].checksum = hook->checksum;
			infos[copied].last_error = ret ? ret : hook->last_error;
			infos[copied].installed = hook->installed ? 1 : 0;
			infos[copied].entry_changed =
				hook->installed &&
				(ret || current_insn != hook->branch_insn);
			strscpy(infos[copied].name, hook->name,
				sizeof(infos[copied].name));
			copied++;
		}
	}
	mutex_unlock(&wksu_hook_mutex);

	if (hook_count)
		*hook_count = copied;
	if (total_hooks)
		*total_hooks = total;
}

void wksu_hook_clear_all(void)
{
	struct wksu_hook *hooks[WKSU_HOOK_REGISTRY_SIZE];
	int count = 0;
	int i;

	mutex_lock(&wksu_hook_mutex);
	for (i = 0; i < WKSU_HOOK_REGISTRY_SIZE; i++) {
		if (wksu_hook_registry[i])
			hooks[count++] = wksu_hook_registry[i];
	}
	mutex_unlock(&wksu_hook_mutex);

	for (i = 0; i < count; i++) {
		wksu_hook_uninstall(hooks[i]);

		mutex_lock(&wksu_hook_mutex);
		if (hooks[i]->installed)
			WARN_ONCE(1,
				  "wksu: hook remained installed during clear_all at %ps\n",
				  hooks[i]->target);
		mutex_unlock(&wksu_hook_mutex);
	}

	/*
	 * wksu_hook_uninstall() queues trampoline free with call_rcu_tasks().
	 * Module exit must wait until callbacks finish before hook.c can go away.
	 */
	rcu_barrier_tasks();
}
