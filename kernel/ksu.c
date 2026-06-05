#include <linux/export.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/workqueue.h>
#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "allowlist.h"
#include "app_profile.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "throne_tracker.h"
#ifndef CONFIG_KSU_SUSFS
#include "syscall_hook_manager.h"
#else
#include "setuid_hook.h"
#include "sucompat.h"
#endif // #ifndef CONFIG_KSU_SUSFS
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"
#include "file_wrapper.h"
#include "selinux/selinux.h"

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                          \
    (defined(CONFIG_ARM64) && defined(MODULE) &&                               \
     !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init
    __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;
atomic_t wksu_hidden_pid_count = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(wksu_hidden_pid_count);

// PID Hiding Logic for Step 4
#include <linux/hashtable.h>
#define WKSU_HIDE_MANUAL (1U << 0)
static DEFINE_HASHTABLE(wksu_hidden_pids, 8);
static DEFINE_SPINLOCK(wksu_pid_lock);
struct wksu_pid_node {
    int pid;
    u64 start_time;
    unsigned int reasons;
    struct hlist_node node;
    struct rcu_head rcu;
};

static u64 wksu_task_start_time(struct task_struct *task)
{
    return task ? READ_ONCE(task->start_time) : 0;
}

static u64 wksu_pid_start_time(int pid)
{
    struct task_struct *task;
    u64 start_time = 0;

    if (pid <= 0)
        return 0;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        start_time = wksu_task_start_time(task);
    rcu_read_unlock();

    return start_time;
}

static unsigned int wksu_pid_hidden_reasons(int pid)
{
    struct wksu_pid_node *node;
    struct task_struct *task;
    u64 start_time = 0;
    unsigned int reasons = 0;

    if (pid <= 0) return false;
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        start_time = wksu_task_start_time(task);
    if (!start_time)
        goto out;
    hash_for_each_possible_rcu(wksu_hidden_pids, node, node, pid) {
        if (node->pid == pid && node->start_time == start_time &&
            node->reasons) {
            reasons = node->reasons;
            break;
        }
    }
out:
    rcu_read_unlock();
    return reasons;
}

bool wksu_is_pid_hidden(int pid) {
    return wksu_pid_hidden_reasons(pid) != 0;
}
EXPORT_SYMBOL_GPL(wksu_is_pid_hidden);

bool wksu_should_hide_pid(int pid)
{
    return wksu_is_pid_hidden(pid);
}
EXPORT_SYMBOL_GPL(wksu_should_hide_pid);

void wksu_get_hidden_stats(int *running, int *total_threads) {
    struct wksu_pid_node *node;
    int r = 0, t = 0;
    int bkt;

    rcu_read_lock();
    hash_for_each_rcu(wksu_hidden_pids, bkt, node, node) {
        struct task_struct *task = find_task_by_vpid(node->pid);
        if (task && wksu_task_start_time(task) == node->start_time) {
            if (READ_ONCE(task->state) == TASK_RUNNING)
                r++;
            t += get_nr_threads(task);
        }
    }
    rcu_read_unlock();

    if (running) *running = r;
    if (total_threads) *total_threads = t;
}
EXPORT_SYMBOL_GPL(wksu_get_hidden_stats);

// Helper to add/remove hidden PID
void wksu_set_pid_hidden_reason(int pid, unsigned int reason, bool hide) {
    struct wksu_pid_node *node;
    struct hlist_node *hnode;
    struct wksu_pid_node *tmp = NULL;
    unsigned long flags;
    u64 start_time;
    bool found = false;

    if (pid <= 0 || !reason) return;
    start_time = wksu_pid_start_time(pid);
    if (!start_time) return;

    spin_lock_irqsave(&wksu_pid_lock, flags);
    
    hash_for_each_possible_safe(wksu_hidden_pids, node, hnode, node, pid) {
        if (node->pid != pid)
            continue;
        if (node->start_time != start_time) {
            hash_del_rcu(&node->node);
            kfree_rcu(node, rcu);
            atomic_dec(&wksu_hidden_pid_count);
            continue;
        }
        found = true;
        tmp = node;
        break;
    }

    if (hide) {
        if (found) {
            tmp->reasons |= reason;
        } else {
            node = kmalloc(sizeof(*node), GFP_ATOMIC);
            if (node) {
                node->pid = pid;
                node->start_time = start_time;
                node->reasons = reason;
                hash_add_rcu(wksu_hidden_pids, &node->node, pid);
                atomic_inc(&wksu_hidden_pid_count);
            }
        }
    } else {
        if (found && tmp) {
            tmp->reasons &= ~reason;
            if (!tmp->reasons) {
                hash_del_rcu(&tmp->node);
                kfree_rcu(tmp, rcu);
                atomic_dec(&wksu_hidden_pid_count);
            }
        }
    }
    spin_unlock_irqrestore(&wksu_pid_lock, flags);
}
EXPORT_SYMBOL_GPL(wksu_set_pid_hidden_reason);

void wksu_set_pid_hidden(int pid, bool hide) {
    wksu_set_pid_hidden_reason(pid, WKSU_HIDE_MANUAL, hide);
}
EXPORT_SYMBOL_GPL(wksu_set_pid_hidden);

void wksu_prune_hidden_pids(void)
{
    struct wksu_pid_node *node;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;

    spin_lock_irqsave(&wksu_pid_lock, flags);
    hash_for_each_safe(wksu_hidden_pids, bkt, tmp, node, node) {
        struct task_struct *task;

        rcu_read_lock();
        task = find_task_by_vpid(node->pid);
        if (task && wksu_task_start_time(task) != node->start_time)
            task = NULL;
        rcu_read_unlock();
        if (task)
            continue;

        hash_del_rcu(&node->node);
        kfree_rcu(node, rcu);
        atomic_dec(&wksu_hidden_pid_count);
    }
    spin_unlock_irqrestore(&wksu_pid_lock, flags);
}
EXPORT_SYMBOL_GPL(wksu_prune_hidden_pids);

int __init kernelsu_init(void)
{
#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
    }

	ksu_feature_init();

	ksu_supercalls_init();

#ifndef CONFIG_KSU_SUSFS
    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();

        ksu_syscall_hook_manager_init();

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        track_throne(false);

        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }

    } else {
        ksu_syscall_hook_manager_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();

        ksu_file_wrapper_init();
    }
#else
    if (ksu_late_loaded) {
        pr_info("late load mode\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();

        ksu_setuid_hook_init();
        ksu_sucompat_init();

        susfs_init();

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        track_throne(false);

        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }
    } else {
        ksu_setuid_hook_init();
        ksu_sucompat_init();

        ksu_allowlist_init();
        ksu_throne_tracker_init();

        susfs_init();
        ksu_file_wrapper_init();
    }
#endif

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
	return 0;
}

extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	ksu_observer_exit();

#ifndef CONFIG_KSU_SUSFS
	if (!ksu_late_loaded) {
		ksu_ksud_exit();
	}

	ksu_syscall_hook_manager_exit();
#endif // #ifndef CONFIG_KSU_SUSFS

	ksu_supercalls_exit();

	ksu_feature_exit();

	if (ksu_cred) {
		put_cred(ksu_cred);
	}
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
