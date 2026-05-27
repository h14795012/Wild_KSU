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
#include <linux/vmalloc.h>

#include <asm/debug-monitors.h>
#include <asm/insn.h>
#include <asm/memory.h>
#include <asm/module.h>
#include <asm/sections.h>

#include "hook.h"

static DEFINE_MUTEX(wksu_hook_mutex);

#define WKSU_TRAMPOLINE_INSN_COUNT 5

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
	u32 branch;
	u32 orig;
	int ret;

	if (!hook || !hook->target || !hook->replacement)
		return -EINVAL;

	if (!wksu_hook_addr_aligned(hook->target) ||
	    !wksu_hook_addr_aligned(hook->replacement))
		return -EINVAL;

	mutex_lock(&wksu_hook_mutex);

	if (hook->installed) {
		ret = 0;
		goto out;
	}

	ret = aarch64_insn_read(hook->target, &orig);
	if (ret)
		goto out;

	if (wksu_hook_entry_busy(orig)) {
		ret = -EBUSY;
		goto out;
	}

	hook->trampoline = NULL;
	ret = wksu_prepare_branch(hook, &branch);
	if (ret)
		goto out;

	ret = wksu_patch_text(hook->target, branch);
	if (ret) {
		wksu_queue_trampoline_free(hook->trampoline);
		hook->trampoline = NULL;
		goto out;
	}

	hook->orig_insn = orig;
	hook->installed = true;

out:
	mutex_unlock(&wksu_hook_mutex);
	return ret;
}

void wksu_hook_uninstall(struct wksu_hook *hook)
{
	int ret;

	if (!hook || !hook->target)
		return;

	mutex_lock(&wksu_hook_mutex);

	if (!hook->installed)
		goto out;

	/*
	 * Restoring target is stop_machine-synchronized by patch_text().
	 * If a CPU was interrupted while executing the trampoline, the target
	 * no longer admits new entrants after this point, and trampoline memory
	 * is released after an RCU-tasks grace period instead of immediately.
	 */
	ret = wksu_patch_text(hook->target, hook->orig_insn);
	if (ret)
		WARN_ONCE(1, "wksu: failed to uninstall hook at %ps: %d\n",
			  hook->target, ret);
	else {
		wksu_queue_trampoline_free(hook->trampoline);
		hook->trampoline = NULL;
		hook->installed = false;
	}

out:
	mutex_unlock(&wksu_hook_mutex);
}
