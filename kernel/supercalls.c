#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/utsname.h> // utsname() and uts_sem
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/oom.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/highmem.h>
#include <linux/bitmap.h>
#include <trace/events/oom.h>
#include <linux/dcache.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "supercalls.h"
#include "arch.h"
#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "kernel_umount.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "file_wrapper.h"
#ifndef CONFIG_KSU_SUSFS
#include "syscall_hook_manager.h"
#endif // #ifndef CONFIG_KSU_SUSFS

#include "tiny_sulog.c"

// Permission check functions
bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
	return true; // No permission check
}

bool allowed_for_su(void)
{
    bool is_allowed =
        is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
    return is_allowed;
}

static int do_grant_root(void __user *arg)
{
	// we already check uid above on allowed_for_su()

    write_sulog('i'); // log ioctl escalation

    pr_info("allow root for: %d\n", current_uid().val);
    escape_with_root_profile();

	return 0;
}

static uint32_t ksuver_override = 0;

static int do_get_info(void __user *arg)
{
    struct ksu_get_info_cmd cmd = { .version = KERNEL_SU_VERSION, .flags = 0 };

#ifdef MODULE
    cmd.flags |= KSU_GET_INFO_FLAG_LKM;
#endif

    if (ksuver_override)
        cmd.version = ksuver_override;

    if (is_manager()) {
        cmd.flags |= KSU_GET_INFO_FLAG_MANAGER;
    }
    if (ksu_late_loaded) {
        cmd.flags |= KSU_GET_INFO_FLAG_LATE_LOAD;
    }
    cmd.features = KSU_FEATURE_MAX;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_report_event(void __user *arg)
{
	struct ksu_report_event_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	switch (cmd.event) {
	case EVENT_POST_FS_DATA: {
		static bool post_fs_data_lock = false;
		if (!post_fs_data_lock) {
			post_fs_data_lock = true;
			if (ksu_late_loaded) {
				pr_info("post-fs-data skipped (late load)\n");
			} else {
				pr_info("post-fs-data triggered\n");
				on_post_fs_data();
			}
		}
		break;
	}
	case EVENT_BOOT_COMPLETED: {
		static bool boot_complete_lock = false;
		if (!boot_complete_lock) {
			boot_complete_lock = true;
			if (ksu_late_loaded) {
				pr_info("boot_complete skipped (late load)\n");
			} else {
				pr_info("boot_complete triggered\n");
				on_boot_completed();
#ifdef CONFIG_KSU_SUSFS
				susfs_start_sdcard_monitor_fn();
#endif // #ifdef CONFIG_KSU_SUSFS
			}
		}
		break;
	}
	case EVENT_MODULE_MOUNTED: {
		pr_info("module mounted!\n");
		on_module_mounted();
		break;
	}
	default:
		break;
	}

	return 0;
}

static int do_set_sepolicy(void __user *arg)
{
	struct ksu_set_sepolicy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	if (cmd.data_len == 0 && cmd.data) {
		return handle_sepolicy_compat((void __user *)cmd.data);
	}

	return handle_sepolicy((void __user *)cmd.data, cmd.data_len);
}

static int do_check_safemode(void __user *arg)
{
	struct ksu_check_safemode_cmd cmd;

	cmd.in_safe_mode = ksu_is_safe_mode();

	if (cmd.in_safe_mode) {
		pr_warn("safemode enabled!\n");
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("check_safemode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_new_get_allow_list_common(void __user *arg, bool allow)
{
	struct ksu_new_get_allow_list_cmd cmd;
	int *arr = NULL;
	int err = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	if (cmd.count) {
		arr = kmalloc(sizeof(int) * cmd.count, GFP_KERNEL);
		if (!arr) {
			return -ENOMEM;
		}
	}

	bool success =
		ksu_get_allow_list(arr, cmd.count, &cmd.count, &cmd.total_count, allow);

	if (!success) {
		err = -EFAULT;
		goto out;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("new_get_allow_list: copy_to_user count failed\n");
		err = -EFAULT;
		goto out;
	}

	if (cmd.count &&
	    copy_to_user(&((struct ksu_new_get_allow_list_cmd *)arg)->uids, arr,
			 sizeof(int) * cmd.count)) {
		pr_err("new_get_allow_list: copy_to_user uids failed\n");
		err = -EFAULT;
	}

out:
	if (arr) {
		kfree(arr);
	}
	return err;
}

static int do_new_get_deny_list(void __user *arg)
{
	return do_new_get_allow_list_common(arg, false);
}

static int do_new_get_allow_list(void __user *arg)
{
	return do_new_get_allow_list_common(arg, true);
}

static int do_get_allow_list_common(void __user *arg, bool allow)
{
	int *arr = NULL;
	int err = 0;
	u16 count;
	u32 out_count;
	static const u16 kSize = 128;

	arr = kmalloc(sizeof(int) * kSize, GFP_KERNEL);
	if (!arr) {
		return -ENOMEM;
	}

	bool success = ksu_get_allow_list(arr, kSize, &count, NULL, allow);

	if (!success) {
		err = -EFAULT;
		goto out;
	}

	out_count = count;

	if (copy_to_user(arg + offsetof(struct ksu_get_allow_list_cmd, count),
			 &out_count, sizeof(u32))) {
		pr_err("get_allow_list: copy_to_user count failed\n");
		err = -EFAULT;
		goto out;
	}

	if (copy_to_user(arg, arr, sizeof(u32) * count)) {
		pr_err("get_allow_list: copy_to_user uids failed\n");
		err = -EFAULT;
	}

out:
	if (arr) {
		kfree(arr);
	}
	return err;
}

static int do_get_deny_list(void __user *arg)
{
	return do_get_allow_list_common(arg, false);
}

static int do_get_allow_list(void __user *arg)
{
	return do_get_allow_list_common(arg, true);
}

static int do_uid_granted_root(void __user *arg)
{
	struct ksu_uid_granted_root_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.granted = ksu_is_allow_uid_for_current(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_granted_root: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_should_umount(void __user *arg)
{
	struct ksu_uid_should_umount_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.should_umount = ksu_uid_should_umount(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_should_umount: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_manager_appid(void __user *arg)
{
	struct ksu_get_manager_appid_cmd cmd;

	cmd.appid = ksu_get_manager_appid();

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_manager_appid: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_app_profile(void __user *arg)
{
	struct ksu_get_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_get_app_profile(&cmd.profile)) {
		return -ENOENT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_app_profile: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_app_profile(void __user *arg)
{
	struct ksu_set_app_profile_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	ret = ksu_set_app_profile(&cmd.profile);
	if (!ret) {
		ksu_persistent_allow_list();
#ifndef CONFIG_KSU_SUSFS
		ksu_mark_running_process();
#endif // #ifndef CONFIG_KSU_SUSFS
	}

	return ret;
}

static int do_get_feature(void __user *arg)
{
	struct ksu_get_feature_cmd cmd;
	bool supported;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_get_feature(cmd.feature_id, &cmd.value, &supported);
	cmd.supported = supported ? 1 : 0;

	if (ret && supported) {
		pr_err("get_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_feature: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_feature(void __user *arg)
{
	struct ksu_set_feature_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_set_feature(cmd.feature_id, cmd.value);
	if (ret) {
		pr_err("set_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	return 0;
}

static int do_get_wrapper_fd(void __user *arg)
{
    if (!ksu_file_sid) {
        return -EINVAL;
    }

    struct ksu_get_wrapper_fd_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        pr_err("get_wrapper_fd: copy_from_user failed\n");
        return -EFAULT;
    }

    return ksu_install_file_wrapper(cmd.fd);
}

static int do_manage_mark(void __user *arg)
{
	struct ksu_manage_mark_cmd cmd;
	int ret = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("manage_mark: copy_from_user failed\n");
		return -EFAULT;
	}

	switch (cmd.operation) {
	case KSU_MARK_GET: {
#ifndef CONFIG_KSU_SUSFS
		// Get task mark status
		ret = ksu_get_task_mark(cmd.pid);
		if (ret < 0) {
			pr_err("manage_mark: get failed for pid %d: %d\n", cmd.pid, ret);
			return ret;
		}
		cmd.result = (u32)ret;
		break;
#else
        if (susfs_is_current_proc_umounted()) {
            ret = 0; // SYSCALL_TRACEPOINT is NOT flagged
        } else {
            ret = 1; // SYSCALL_TRACEPOINT is flagged
        }
        pr_info("manage_mark: ret for pid %d: %d\n", cmd.pid, ret);
        cmd.result = (u32)ret;
        break;
#endif // #ifndef CONFIG_KSU_SUSFS
	}
	case KSU_MARK_MARK: {
#ifndef CONFIG_KSU_SUSFS
		if (cmd.pid == 0) {
			ksu_mark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, true);
			if (ret < 0) {
				pr_err("manage_mark: set_mark failed for pid %d: %d\n", cmd.pid,
					ret);
				return ret;
			}
		}
#else
        if (cmd.pid != 0) {
            return ret;
        }
#endif // #ifndef CONFIG_KSU_SUSFS
		break;
	}
	case KSU_MARK_UNMARK: {
#ifndef CONFIG_KSU_SUSFS
		if (cmd.pid == 0) {
			ksu_unmark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, false);
			if (ret < 0) {
				pr_err("manage_mark: set_unmark failed for pid %d: %d\n",
					cmd.pid, ret);
				return ret;
			}
		}
#else
        if (cmd.pid != 0) {
            return ret;
        }
#endif // #ifndef CONFIG_KSU_SUSFS
		break;
	}
	case KSU_MARK_REFRESH: {
#ifndef CONFIG_KSU_SUSFS
		ksu_mark_running_process();
		pr_info("manage_mark: refreshed running processes\n");
#else
        pr_info("susfs: cmd: KSU_MARK_REFRESH: do nothing\n");
#endif // #ifndef CONFIG_KSU_SUSFS
		break;
	}
	default: {
		pr_err("manage_mark: invalid operation %u\n", cmd.operation);
		return -EINVAL;
	}
	}
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("manage_mark: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_hook_mode(void __user *arg)
{
	struct ksu_get_hook_mode_cmd cmd = {0};

#if !defined(CONFIG_KSU_SUSFS) && defined(CONFIG_KPROBES)
	strscpy(cmd.mode, "Kprobes", sizeof(cmd.mode));
#elif defined(CONFIG_KSU_SUSFS)
	strscpy(cmd.mode, "Inline (SUSFS)", sizeof(cmd.mode));
#else
	strscpy(cmd.mode, "Inline", sizeof(cmd.mode));
#endif // CONFIG_KSU_SUSFS

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_hook_mode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_version_tag(void __user *arg)
{
	struct ksu_get_version_tag_cmd cmd = {0};

	strscpy(cmd.tag, KERNEL_SU_VERSION_TAG, sizeof(cmd.tag));

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version_tag: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_nuke_ext4_sysfs(void __user *arg)
{
    struct ksu_nuke_ext4_sysfs_cmd cmd;
    char mnt[256];
    long ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    if (!cmd.arg)
        return -EINVAL;

    memset(mnt, 0, sizeof(mnt));

    ret = strncpy_from_user(mnt, cmd.arg, sizeof(mnt));
    if (ret < 0) {
        pr_err("nuke ext4 copy mnt failed: %ld\\n", ret);
        return -EFAULT; // 或者 return ret;
    }

    if (ret == sizeof(mnt)) {
        pr_err("nuke ext4 mnt path too long\\n");
        return -ENAMETOOLONG;
    }

    pr_info("do_nuke_ext4_sysfs: %s\n", mnt);

    return nuke_ext4_sysfs(mnt);
}

struct list_head mount_list = LIST_HEAD_INIT(mount_list);
DECLARE_RWSEM(mount_list_lock);

static int add_try_umount(void __user *arg)
{
    struct mount_entry *new_entry, *entry, *tmp;
    struct ksu_add_try_umount_cmd cmd;
    char buf[256] = { 0 };

    if (copy_from_user(&cmd, arg, sizeof cmd))
        return -EFAULT;

    switch (cmd.mode) {
    case KSU_UMOUNT_WIPE: {
        struct mount_entry *entry, *tmp;
        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            pr_info("wipe_umount_list: removing entry: %s\n",
                    entry->umountable);
            list_del(&entry->list);
            kfree(entry->umountable);
            kfree(entry);
        }
        up_write(&mount_list_lock);

        return 0;
    }

    case KSU_UMOUNT_ADD: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg, 256);
        if (len <= 0)
            return -EFAULT;

        buf[sizeof(buf) - 1] = '\0';

        new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
        if (!new_entry)
            return -ENOMEM;

        new_entry->umountable = kstrdup(buf, GFP_KERNEL);
        if (!new_entry->umountable) {
            kfree(new_entry);
			return -ENOMEM;
        }

        down_write(&mount_list_lock);

        // disallow dupes
        // if this gets too many, we can consider moving this whole task to a kthread
        list_for_each_entry (entry, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                pr_info("cmd_add_try_umount: %s is already here!\n", buf);
                up_write(&mount_list_lock);
                kfree(new_entry->umountable);
                kfree(new_entry);
                return -1;
            }
        }

        // now check flags and add
        // this also serves as a null check
        if (cmd.flags)
            new_entry->flags = cmd.flags;
        else
            new_entry->flags = 0;

        // debug
        list_add(&new_entry->list, &mount_list);
        up_write(&mount_list_lock);
        pr_info("cmd_add_try_umount: %s added!\n", buf);

        return 0;
    }

    // this is just strcmp'd wipe anyway
    case KSU_UMOUNT_DEL: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg,
                                     sizeof(buf) - 1);
        if (len <= 0)
            return -EFAULT;

        buf[sizeof(buf) - 1] = '\0';

        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                pr_info("cmd_add_try_umount: entry removed: %s\n",
                        entry->umountable);
                list_del(&entry->list);
                kfree(entry->umountable);
                kfree(entry);
            }
        }
        up_write(&mount_list_lock);

        return 0;
    }

    // this way userspace can deduce the memory it has to prepare.
    case KSU_UMOUNT_GETSIZE: {
        // check for pointer first
        if (!cmd.arg)
            return -EFAULT;
        
        size_t total_size = 0; // size of list in bytes

        down_read(&mount_list_lock);
        list_for_each_entry(entry, &mount_list, list) {
            total_size = total_size + strlen(entry->umountable) + 1; // + 1 for \0
        }
        up_read(&mount_list_lock);

        // debug
        // pr_info("cmd_add_try_umount: total_size: %zu\n", total_size);
            
        if (copy_to_user((size_t __user *)cmd.arg, &total_size, sizeof(total_size)))
            return -EFAULT;

        return 0;
    }
        
    // WARNING! this is straight up pointerwalking.
    // this way we dont need to redefine the ioctl defs.
    // this also avoids us needing to kmalloc
    // userspace have to send pointer to memory (malloc/alloca) or pointer to a VLA.
    case KSU_UMOUNT_GETLIST: {
        // check for pointer first
        if (!cmd.arg)
            return -EFAULT;
            
        char *user_buf = (char *)cmd.arg;

        down_read(&mount_list_lock);
        list_for_each_entry(entry, &mount_list, list) {

            //debug
            //pr_info("cmd_add_try_umount: entry: %s\n", entry->umountable);
            
            if (copy_to_user((char __user *)user_buf, entry->umountable, strlen(entry->umountable) + 1 )) {
                up_read(&mount_list_lock);
                return -EFAULT;
            }

            // walk it! +1 for null terminator
            user_buf = user_buf + strlen(entry->umountable) + 1;
        }
        up_read(&mount_list_lock);

        return 0;
    }

    default: {
        pr_err("cmd_add_try_umount: invalid operation %u\n", cmd.mode);
        return -EINVAL;
    }

    } // switch(cmd.mode)

    return 0;
}

static int do_manage_pid_hide(void __user *arg)
{
    struct ksu_manage_pid_hide_cmd cmd;
    extern void wksu_set_pid_hidden(int pid, bool hide);

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    wksu_set_pid_hidden(cmd.pid, cmd.hide);
    return 0;
}

static int do_mem_rw(void __user *arg)
{
    struct ksu_mem_rw_cmd cmd;
    struct task_struct *task;
    void *page_buf;
    int ret = 0;
    extern bool wksu_is_pid_hidden(int pid);

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    // Scope restriction: only allow hidden caller processes to use MEM_RW.
    if (!wksu_is_pid_hidden(task_tgid_vnr(current))) {
        return -EACCES;
    }

    task = find_get_task_by_vpid(cmd.pid);
    if (!task) return -ESRCH;

    page_buf = (void *)__get_free_page(GFP_KERNEL);
    if (!page_buf) {
        put_task_struct(task);
        return -ENOMEM;
    }

    while (cmd.len > 0) {
        size_t bytes = min_t(size_t, cmd.len, PAGE_SIZE);

        if (cmd.write) {
            if (copy_from_user(page_buf, (void __user *)cmd.buf, bytes)) {
                ret = -EFAULT;
                break;
            }
            if (access_process_vm(task, (unsigned long)cmd.addr, page_buf, bytes, FOLL_FORCE | FOLL_WRITE) != bytes) {
                ret = -EIO;
                break;
            }
        } else {
            if (access_process_vm(task, (unsigned long)cmd.addr, page_buf, bytes, FOLL_FORCE) != bytes) {
                ret = -EIO;
                break;
            }
            if (copy_to_user((void __user *)cmd.buf, page_buf, bytes)) {
                ret = -EFAULT;
                break;
            }
        }

        cmd.addr += bytes;
        cmd.buf += bytes;
        cmd.len -= bytes;
    }

    free_page((unsigned long)page_buf);
    put_task_struct(task);
    return ret;
}
static bool ksu_process_name_matches(const char *candidate,
                                     size_t candidate_len,
                                     const char *target,
                                     size_t target_len)
{
    if (!candidate || !target || candidate_len == 0 || target_len == 0)
        return false;

    while (candidate_len > 0 && *candidate == '\0') {
        candidate++;
        candidate_len--;
    }
    if (candidate_len == 0)
        return false;

    if (candidate_len >= target_len && !strncmp(candidate, target, target_len)) {
        char next = candidate[target_len];
        if (next == '\0' || next == ':' || next == ' ' || next == '\n')
            return true;
    }

    return false;
}

static bool ksu_cmdline_matches_process(const char *cmdline,
                                        int cmdline_len,
                                        const char *target,
                                        size_t target_len)
{
    int pos = 0;

    if (!cmdline || cmdline_len <= 0)
        return false;

    while (pos < cmdline_len) {
        const char *candidate;
        int start;
        size_t candidate_len;

        while (pos < cmdline_len && cmdline[pos] == '\0')
            pos++;
        if (pos >= cmdline_len)
            break;

        start = pos;
        while (pos < cmdline_len && cmdline[pos] != '\0')
            pos++;

        candidate = cmdline + start;
        candidate_len = pos - start;
        if (ksu_process_name_matches(candidate, candidate_len, target, target_len))
            return true;
    }

    return false;
}

static int do_find_pid(void __user *arg)
{
    struct ksu_find_pid_cmd cmd;
    struct task_struct *p;
    struct task_struct **tasks;
    pid_t *tgids;
    int count = 0, i, max_tasks = 2048;
    pid_t found_pid = -1;
    size_t name_len;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    cmd.process_name[sizeof(cmd.process_name) - 1] = '\0';
    if (cmd.process_name[0] == '\0')
        return -EINVAL;

    name_len = strnlen(cmd.process_name, sizeof(cmd.process_name));

    tasks = kmalloc_array(max_tasks, sizeof(*tasks), GFP_KERNEL);
    tgids = kmalloc_array(max_tasks, sizeof(*tgids), GFP_KERNEL);
    if (!tasks || !tgids) {
        kfree(tasks);
        kfree(tgids);
        return -ENOMEM;
    }

    rcu_read_lock();
    for_each_process(p) {
        if (count >= max_tasks)
            break;
        get_task_struct(p);
        tasks[count] = p;
        tgids[count] = task_tgid_vnr(p);
        count++;
    }
    rcu_read_unlock();

    for (i = 0; i < count; i++) {
        if (found_pid < 0) {
            char comm[TASK_COMM_LEN] = {0};
            char buf[256] = {0};
            int len;

            get_task_comm(comm, tasks[i]);
            if (ksu_process_name_matches(comm, strnlen(comm, sizeof(comm)), cmd.process_name, name_len)) {
                found_pid = tgids[i];
                goto put_task;
            }

            len = get_cmdline(tasks[i], buf, sizeof(buf) - 1);
            if (len > 0) {
                if (len >= (int)sizeof(buf))
                    len = sizeof(buf) - 1;
                buf[len] = '\0';
                if (ksu_cmdline_matches_process(buf, len, cmd.process_name, name_len))
                    found_pid = tgids[i];
            }
        }
put_task:
        put_task_struct(tasks[i]);
    }

    kfree(tasks);
    kfree(tgids);

    cmd.pid = found_pid;
    if (copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;

    return found_pid > 0 ? 0 : -ESRCH;
}

static int do_query_module(void __user *arg)
{
	struct ksu_query_module_cmd cmd;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	const char *query_name;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.module_name[sizeof(cmd.module_name) - 1] = '\0';
	query_name = strrchr(cmd.module_name, '/');
	query_name = query_name ? query_name + 1 : cmd.module_name;
	if (query_name[0] == '\0') {
		return -EINVAL;
	}

	if (cmd.pid <= 0) {
		return -EINVAL;
	}

	task = find_get_task_by_vpid(cmd.pid);
	if (!task) {
		return -ESRCH;
	}

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -EINVAL;
	}

	cmd.found = 0;
	cmd.base = 0;
	cmd.end = 0;
	cmd.size = 0;

	mmap_read_lock(mm);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file) {
			const char *fname = vma->vm_file->f_path.dentry->d_name.name;
			if (fname && !strcmp(fname, query_name)) {
				__u64 file_offset = ((__u64)vma->vm_pgoff << PAGE_SHIFT);
				__u64 curr_base;

				if (vma->vm_start < file_offset)
					continue;
				curr_base = vma->vm_start - file_offset;
				if (!cmd.found) {
					cmd.base = curr_base;
					cmd.end = vma->vm_end;
					cmd.found = 1;
				} else {
					if (curr_base < cmd.base)
						cmd.base = curr_base;
					if (vma->vm_end > cmd.end)
						cmd.end = vma->vm_end;
				}
			}
		}
	}
	mmap_read_unlock(mm);

	mmput(mm);
	put_task_struct(task);

	if (cmd.found) {
		cmd.size = cmd.end - cmd.base;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		return -EFAULT;
	}

	return cmd.found ? 0 : -ENOENT;
}

static pid_t lock_owner_pid = 0;
static DEFINE_MUTEX(instance_lock_mutex);

static int do_instance_lock(void __user *arg)
{
    struct ksu_instance_lock_cmd cmd;
    pid_t current_pid = task_tgid_vnr(current);
    int ret = 0;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    mutex_lock(&instance_lock_mutex);

    if (cmd.op == 1) { // Acquire
        if (lock_owner_pid == 0) {
            // No owner, acquire directly
            lock_owner_pid = current_pid;
            ret = 0;
        } else if (lock_owner_pid == current_pid) {
            // Already owned by current process (idempotent)
            ret = 0;
        } else {
            struct task_struct *task = find_get_task_by_vpid(lock_owner_pid);
            if (!task) {
                lock_owner_pid = current_pid;
                ret = 0;
            } else {
                put_task_struct(task);
                ret = -EBUSY;
            }
        }
    } else if (cmd.op == 0) { // Release
        if (lock_owner_pid == current_pid) {
            lock_owner_pid = 0;
            ret = 0;
        } else {
            ret = -EPERM;
        }
    } else {
        ret = -EINVAL;
    }

    mutex_unlock(&instance_lock_mutex);
    return ret;
}

static int do_oom_score_adj(void __user *arg)
{
	struct ksu_oom_score_adj_cmd cmd;
	struct task_struct *task;
	struct mm_struct *mm = NULL;
	int err = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	if (cmd.pid <= 0)
		return -EINVAL;

	task = find_get_task_by_vpid(cmd.pid);
	if (!task)
		return -ESRCH;

	cmd.result = 0;

	if (cmd.op == KSU_OOM_SCORE_ADJ_SET) { // Set
		if (cmd.oom_score_adj < OOM_SCORE_ADJ_MIN ||
		    cmd.oom_score_adj > OOM_SCORE_ADJ_MAX) {
			err = -EINVAL;
			goto out_put;
		}

		mutex_lock(&oom_adj_mutex);

		if (cmd.oom_score_adj < task->signal->oom_score_adj_min &&
		    !capable(CAP_SYS_RESOURCE)) {
			err = -EACCES;
			goto out_unlock;
		}

		if (!task->vfork_done) {
			struct task_struct *p = find_lock_task_mm(task);
			if (p) {
				if (test_bit(MMF_MULTIPROCESS, &p->mm->flags)) {
					mm = p->mm;
					mmgrab(mm);
				}
				task_unlock(p);
			}
		}

		task->signal->oom_score_adj = cmd.oom_score_adj;
		if (has_capability_noaudit(current, CAP_SYS_RESOURCE))
			task->signal->oom_score_adj_min = (short)cmd.oom_score_adj;
		trace_oom_score_adj_update(task);

		if (mm) {
			struct task_struct *p;

			rcu_read_lock();
			for_each_process(p) {
				if (same_thread_group(task, p))
					continue;

				if (p->flags & PF_KTHREAD || is_global_init(p))
					continue;

				task_lock(p);
				if (!p->vfork_done && process_shares_mm(p, mm)) {
					p->signal->oom_score_adj = cmd.oom_score_adj;
					if (has_capability_noaudit(current, CAP_SYS_RESOURCE))
						p->signal->oom_score_adj_min = (short)cmd.oom_score_adj;
				}
				task_unlock(p);
			}
			rcu_read_unlock();
			mmdrop(mm);
		}

	out_unlock:
		mutex_unlock(&oom_adj_mutex);
	} else if (cmd.op == KSU_OOM_SCORE_ADJ_GET) { // Get
		cmd.oom_score_adj = task->signal->oom_score_adj;
	} else {
		err = -EINVAL;
	}

	cmd.result = err;
	if (copy_to_user(arg, &cmd, sizeof(cmd)) && err == 0)
		err = -EFAULT;

out_put:
	put_task_struct(task);
	return err;
}

static const char *ksu_query_basename(char *name)
{
	char *base;

	name[255] = '\0';
	base = strrchr(name, '/');
	base = base ? base + 1 : name;
	return base;
}

static bool ksu_vma_file_name_equals(struct vm_area_struct *vma, const char *name)
{
	const char *fname;

	if (!vma->vm_file || !name || name[0] == '\0')
		return false;

	fname = vma->vm_file->f_path.dentry->d_name.name;
	return fname && !strcmp(fname, name);
}

static bool ksu_vma_is_rw_private_anon(struct vm_area_struct *vma)
{
	if (vma->vm_file)
		return false;
	if (!(vma->vm_flags & VM_READ) || !(vma->vm_flags & VM_WRITE))
		return false;
	return !(vma->vm_flags & VM_MAYSHARE);
}

static bool ksu_copy_anon_vma_name(struct mm_struct *mm, struct vm_area_struct *vma,
					  char *out, size_t out_size)
{
	const char __user *name = vma_get_anon_name(vma);
	unsigned long page_start_vaddr;
	unsigned long page_offset;
	unsigned long max_len;
	size_t written = 0;

	if (!name || !out || out_size == 0)
		return false;

	out[0] = '\0';
	page_start_vaddr = (unsigned long)name & PAGE_MASK;
	page_offset = (unsigned long)name - page_start_vaddr;
	max_len = min_t(unsigned long, NAME_MAX, out_size - 1);

	while (max_len > 0) {
		struct page *page;
		const char *kaddr;
		long pinned;
		int len;
		int copy_len;

		pinned = get_user_pages_remote(mm, page_start_vaddr, 1, 0, &page, NULL, NULL);
		if (pinned < 1)
			break;

		kaddr = (const char *)kmap(page);
		len = min_t(unsigned long, max_len, PAGE_SIZE - page_offset);
		copy_len = strnlen(kaddr + page_offset, len);
		memcpy(out + written, kaddr + page_offset, copy_len);
		kunmap(page);
		put_user_page(page);

		written += copy_len;
		out[written] = '\0';
		if (copy_len != len)
			return true;

		max_len -= len;
		page_offset = 0;
		page_start_vaddr += PAGE_SIZE;
	}

	out[written] = '\0';
	return written > 0;
}

static void ksu_fill_vma_result(struct ksu_query_vma_cmd *cmd,
				       struct mm_struct *mm,
				       struct vm_area_struct *vma)
{
	cmd->base = vma->vm_start;
	cmd->end = vma->vm_end;
	cmd->size = vma->vm_end - vma->vm_start;
	cmd->offset = (__u64)vma->vm_pgoff << PAGE_SHIFT;
	cmd->prot = (__u64)vma->vm_flags;
	cmd->flags = 0;
	cmd->found = 1;
	cmd->name[0] = '\0';

	if (vma->vm_file) {
		char *tmp_buf;
		char *path_ptr;

		cmd->flags |= KSU_QUERY_VMA_FLAG_NAMED;
		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (tmp_buf) {
			path_ptr = d_path(&vma->vm_file->f_path, tmp_buf, PATH_MAX);
			if (!IS_ERR(path_ptr))
				strscpy(cmd->name, path_ptr, sizeof(cmd->name));
			else
				strscpy(cmd->name, vma->vm_file->f_path.dentry->d_name.name,
					sizeof(cmd->name));
			kfree(tmp_buf);
		}
		return;
	}

	if (ksu_copy_anon_vma_name(mm, vma, cmd->name, sizeof(cmd->name))) {
		if (!strcmp(cmd->name, ".bss"))
			cmd->flags |= KSU_QUERY_VMA_FLAG_ANON_BSS;
		return;
	}

	if (vma->vm_ops && vma->vm_ops->name) {
		const char *name = vma->vm_ops->name(vma);
		if (name) {
			strscpy(cmd->name, name, sizeof(cmd->name));
			return;
		}
	}

	if (arch_vma_name(vma)) {
		strscpy(cmd->name, arch_vma_name(vma), sizeof(cmd->name));
	} else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
		strscpy(cmd->name, "[heap]", sizeof(cmd->name));
	} else if (vma->vm_start <= mm->start_stack && vma->vm_end >= mm->start_stack) {
		strscpy(cmd->name, "[stack]", sizeof(cmd->name));
	} else {
		strscpy(cmd->name, "[anon]", sizeof(cmd->name));
	}
}

static int do_query_vma(void __user *arg)
{
	struct ksu_query_vma_cmd cmd;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	const char *query_name;
	int err = -ENOENT;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	if (cmd.pid <= 0)
		return -EINVAL;

	cmd.name[sizeof(cmd.name) - 1] = '\0';
	query_name = ksu_query_basename(cmd.name);
	if ((cmd.type == KSU_QUERY_VMA_MODULE_BASE ||
	     cmd.type == KSU_QUERY_VMA_MODULE_REGION ||
	     cmd.type == KSU_QUERY_VMA_MODULE_BSS ||
	     cmd.type == KSU_QUERY_VMA_MODULE_ANON_BSS ||
	     cmd.type == KSU_QUERY_VMA_CLUSTER_SEGMENT) &&
	    query_name[0] == '\0')
		return -EINVAL;

	task = find_get_task_by_vpid(cmd.pid);
	if (!task)
		return -ESRCH;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -EINVAL;
	}

	cmd.found = 0;
	cmd.base = 0;
	cmd.end = 0;
	cmd.size = 0;
	cmd.offset = 0;
	cmd.prot = 0;
	cmd.flags = 0;

	mmap_read_lock(mm);
	switch (cmd.type) {
	case KSU_QUERY_VMA_MODULE_BASE: {
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (ksu_vma_file_name_equals(vma, query_name)) {
				__u64 file_offset = (__u64)vma->vm_pgoff << PAGE_SHIFT;
				__u64 curr_base;

				if (vma->vm_start < file_offset)
					continue;
				curr_base = vma->vm_start - file_offset;
				if (!cmd.found) {
					cmd.base = curr_base;
					cmd.end = vma->vm_end;
					cmd.found = 1;
				} else {
					if (curr_base < cmd.base)
						cmd.base = curr_base;
					if (vma->vm_end > cmd.end)
						cmd.end = vma->vm_end;
				}
			}
		}
		if (cmd.found) {
			cmd.size = cmd.end - cmd.base;
			cmd.flags = KSU_QUERY_VMA_FLAG_NAMED;
			err = 0;
		}
		break;
	}
	case KSU_QUERY_VMA_MEM_REGION:
		vma = find_vma(mm, (unsigned long)cmd.addr);
		if (vma && (unsigned long)cmd.addr >= vma->vm_start &&
		    (vma->vm_flags & VM_READ)) {
			ksu_fill_vma_result(&cmd, mm, vma);
			err = 0;
		}
		break;
	case KSU_QUERY_VMA_MODULE_REGION: {
		__u32 match_idx = 0;
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (!ksu_vma_file_name_equals(vma, query_name))
				continue;
			if (match_idx == cmd.index) {
				ksu_fill_vma_result(&cmd, mm, vma);
				err = 0;
				break;
			}
			match_idx++;
		}
		break;
	}
	case KSU_QUERY_VMA_MODULE_BSS: {
		__u64 module_file_end = 0;
		__u64 scan_limit = 0;
		__u32 match_idx = 0;

		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (ksu_vma_file_name_equals(vma, query_name))
				module_file_end = vma->vm_end;
		}
		if (!module_file_end)
			break;

		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (vma->vm_start < module_file_end)
				continue;
			if (vma->vm_file) {
				scan_limit = vma->vm_start;
				break;
			}
		}

		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (vma->vm_start < module_file_end)
				continue;
			if (scan_limit && vma->vm_start >= scan_limit)
				break;
			if (!ksu_vma_is_rw_private_anon(vma))
				continue;
			if (match_idx == cmd.index) {
				ksu_fill_vma_result(&cmd, mm, vma);
				err = 0;
				break;
			}
			match_idx++;
		}
		break;
	}
	case KSU_QUERY_VMA_MODULE_ANON_BSS: {
		__u64 last_named_end = 0;
		bool previous_was_target = false;

		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (ksu_vma_file_name_equals(vma, query_name)) {
				last_named_end = vma->vm_end;
				previous_was_target = true;
				continue;
			}

			if (previous_was_target && !vma->vm_file &&
			    vma->vm_start == last_named_end) {
				char anon_name[NAME_MAX + 1];
				if (ksu_copy_anon_vma_name(mm, vma, anon_name, sizeof(anon_name)) &&
				    !strcmp(anon_name, ".bss")) {
					ksu_fill_vma_result(&cmd, mm, vma);
					err = 0;
				}
			}
			previous_was_target = false;
		}
		break;
	}
	case KSU_QUERY_VMA_CLUSTER_SEGMENT: {
		bool in_cluster = false;
		__u32 match_idx = 0;

		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			bool is_match = ksu_vma_file_name_equals(vma, query_name);

			if (is_match) {
				in_cluster = true;
			} else if (in_cluster && vma->vm_file) {
				in_cluster = false;
				continue;
			} else if (!in_cluster) {
				continue;
			}

			if (match_idx == cmd.index) {
				ksu_fill_vma_result(&cmd, mm, vma);
				err = 0;
				break;
			}
			match_idx++;
		}
		break;
	}
	case KSU_QUERY_VMA_BY_INDEX: {
		__u32 match_idx = 0;
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (match_idx == cmd.index) {
				ksu_fill_vma_result(&cmd, mm, vma);
				err = 0;
				break;
			}
			match_idx++;
		}
		break;
	}
	case KSU_QUERY_VMA_COUNT: {
		__u64 count = 0;
		for (vma = mm->mmap; vma; vma = vma->vm_next)
			count++;
		cmd.size = count;
		cmd.found = 1;
		err = 0;
		break;
	}
	default:
		err = -EINVAL;
		break;
	}
	mmap_read_unlock(mm);

	mmput(mm);
	put_task_struct(task);

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return err;
}

static int do_get_proc_stats(void __user *arg)
{
	struct ksu_proc_stats_cmd cmd;
	struct task_struct *task;
	struct mm_struct *mm;
	struct files_struct *files;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	if (cmd.pid <= 0)
		return -EINVAL;

	task = find_get_task_by_vpid(cmd.pid);
	if (!task)
		return -ESRCH;

	cmd.threads = task->signal->nr_threads;
	cmd.oom_score_adj = task->signal->oom_score_adj;
	cmd.fd_count = 0;

	files = get_files_struct(task);
	if (files) {
		struct fdtable *fdt;
		rcu_read_lock();
		fdt = files_fdtable(files);
		cmd.fd_count = bitmap_weight(fdt->open_fds, fdt->max_fds);
		rcu_read_unlock();
		put_files_struct(files);
	}

	mm = get_task_mm(task);
	if (mm) {
		cmd.rss = (u64)get_mm_rss(mm) << PAGE_SHIFT;
		cmd.vmsize = (u64)mm->total_vm << PAGE_SHIFT;
		mmput(mm);
	} else {
		cmd.rss = 0;
		cmd.vmsize = 0;
	}

	put_task_struct(task);

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return 0;
}

struct ksu_input_query_data {
	u32 target_index;
	u32 current_index;
	struct ksu_input_device_query_cmd *cmd;
};

static void ksu_fill_abs_range(struct input_dev *idev, unsigned int code,
				       __s32 *min, __s32 *max)
{
	if (idev && idev->absinfo && test_bit(code, idev->absbit)) {
		*min = idev->absinfo[code].minimum;
		*max = idev->absinfo[code].maximum;
	} else {
		*min = 0;
		*max = 0;
	}
}

static int ksu_input_device_visitor(struct device *dev, void *data)
{
	struct ksu_input_query_data *idq = data;
	const char *name = dev_name(dev);

	if (name && !strncmp(name, "event", 5)) {
		if (idq->current_index == idq->target_index) {
			snprintf(idq->cmd->path, sizeof(idq->cmd->path), "/dev/input/%s", name);
			if (dev->parent) {
				struct input_dev *id = to_input_dev(dev->parent);

				strscpy(idq->cmd->name, id->name ? id->name : "", sizeof(idq->cmd->name));
				idq->cmd->bustype = id->id.bustype;
				idq->cmd->vendor = id->id.vendor;
				idq->cmd->product = id->id.product;
				idq->cmd->version = id->id.version;
				ksu_fill_abs_range(id, ABS_X, &idq->cmd->abs_x_min,
						   &idq->cmd->abs_x_max);
				ksu_fill_abs_range(id, ABS_Y, &idq->cmd->abs_y_min,
						   &idq->cmd->abs_y_max);
				ksu_fill_abs_range(id, ABS_MT_POSITION_X, &idq->cmd->mt_x_min,
						   &idq->cmd->mt_x_max);
				ksu_fill_abs_range(id, ABS_MT_POSITION_Y, &idq->cmd->mt_y_min,
						   &idq->cmd->mt_y_max);
				idq->cmd->slot_count = id->mt ? id->mt->num_slots : 0;
				idq->cmd->is_direct = test_bit(INPUT_PROP_DIRECT, id->propbit) ? 1 : 0;
				idq->cmd->is_pointer = test_bit(INPUT_PROP_POINTER, id->propbit) ? 1 : 0;
				idq->cmd->has_btn_touch = test_bit(BTN_TOUCH, id->keybit) ? 1 : 0;
				idq->cmd->has_btn_tool_finger = test_bit(BTN_TOOL_FINGER, id->keybit) ? 1 : 0;
				idq->cmd->has_mt_slot = test_bit(ABS_MT_SLOT, id->absbit) ? 1 : 0;
				idq->cmd->has_mt_tracking_id = test_bit(ABS_MT_TRACKING_ID, id->absbit) ? 1 : 0;
				idq->cmd->has_mt_position =
					(test_bit(ABS_MT_POSITION_X, id->absbit) &&
					 test_bit(ABS_MT_POSITION_Y, id->absbit)) ? 1 : 0;
				idq->cmd->has_mt_pressure = test_bit(ABS_MT_PRESSURE, id->absbit) ? 1 : 0;
				idq->cmd->has_mt_touch_major = test_bit(ABS_MT_TOUCH_MAJOR, id->absbit) ? 1 : 0;
				idq->cmd->has_mt_width_major = test_bit(ABS_MT_WIDTH_MAJOR, id->absbit) ? 1 : 0;
				idq->cmd->has_abs_x = test_bit(ABS_X, id->absbit) ? 1 : 0;
				idq->cmd->has_abs_y = test_bit(ABS_Y, id->absbit) ? 1 : 0;
				ksu_fill_abs_range(id, ABS_MT_PRESSURE, &idq->cmd->pressure_min,
						   &idq->cmd->pressure_max);
				ksu_fill_abs_range(id, ABS_MT_TRACKING_ID, &idq->cmd->tracking_id_min,
						   &idq->cmd->tracking_id_max);
			}
			idq->cmd->found = 1;
			return 1; // Stop iteration
		}
		idq->current_index++;
	}
	return 0;
}

static int do_input_device_query(void __user *arg)
{
	struct ksu_input_device_query_cmd cmd;
	struct ksu_input_query_data data;
	__u32 requested_index;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	requested_index = cmd.index;
	memset(&cmd, 0, sizeof(cmd));
	cmd.index = requested_index;
	data.target_index = requested_index;
	data.current_index = 0;
	data.cmd = &cmd;

	class_for_each_device(&input_class, NULL, &data, ksu_input_device_visitor);

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return cmd.found ? 0 : -ENOENT;
}

struct ksu_input_find_data {
	u32 target_index;
	u32 current_index;
	struct input_dev *idev;
};

static int ksu_input_find_visitor(struct device *dev, void *data)
{
	struct ksu_input_find_data *find = data;
	const char *name = dev_name(dev);

	if (!name || strncmp(name, "event", 5))
		return 0;

	if (find->current_index == find->target_index) {
		if (dev->parent)
			find->idev = input_get_device(to_input_dev(dev->parent));
		return 1;
	}

	find->current_index++;
	return 0;
}

static struct input_dev *ksu_find_input_dev_by_index(u32 index)
{
	struct ksu_input_find_data find;

	memset(&find, 0, sizeof(find));
	find.target_index = index;
	class_for_each_device(&input_class, NULL, &find, ksu_input_find_visitor);
	return find.idev;
}

static DEFINE_MUTEX(ksu_input_inject_mutex);
static struct input_dev *ksu_input_inject_dev;
static u32 ksu_input_inject_index = (u32)-1;

static void ksu_input_inject_close_locked(void)
{
	if (ksu_input_inject_dev) {
		input_put_device(ksu_input_inject_dev);
		ksu_input_inject_dev = NULL;
	}
	ksu_input_inject_index = (u32)-1;
}

static int do_input_inject(void __user *arg)
{
	struct ksu_input_inject_cmd cmd;
	struct input_dev *idev;
	int err = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	cmd.result = 0;

	switch (cmd.op) {
	case KSU_INPUT_INJECT_OPEN:
		idev = ksu_find_input_dev_by_index(cmd.index);
		if (!idev) {
			err = -ENODEV;
			break;
		}
		mutex_lock(&ksu_input_inject_mutex);
		ksu_input_inject_close_locked();
		ksu_input_inject_dev = idev;
		ksu_input_inject_index = cmd.index;
		mutex_unlock(&ksu_input_inject_mutex);
		break;
	case KSU_INPUT_INJECT_EVENT:
		if (cmd.type > EV_MAX) {
			err = -EINVAL;
			break;
		}
		mutex_lock(&ksu_input_inject_mutex);
		idev = input_get_device(ksu_input_inject_dev);
		mutex_unlock(&ksu_input_inject_mutex);
		if (!idev) {
			err = -ENODEV;
			break;
		}
		input_event(idev, cmd.type, cmd.code, cmd.value);
		input_put_device(idev);
		break;
	case KSU_INPUT_INJECT_CLOSE:
		mutex_lock(&ksu_input_inject_mutex);
		ksu_input_inject_close_locked();
		mutex_unlock(&ksu_input_inject_mutex);
		break;
	case KSU_INPUT_INJECT_STATUS:
		mutex_lock(&ksu_input_inject_mutex);
		cmd.index = ksu_input_inject_index;
		cmd.result = ksu_input_inject_dev ? 1 : 0;
		mutex_unlock(&ksu_input_inject_mutex);
		break;
	default:
		err = -EINVAL;
		break;
	}

	if (err)
		cmd.result = err;

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return err;
}


#define KSU_TOUCH_RING_SIZE 512

static DEFINE_MUTEX(ksu_touch_reader_mutex);
static DEFINE_SPINLOCK(ksu_touch_reader_lock);
static DECLARE_WAIT_QUEUE_HEAD(ksu_touch_reader_wait);
static struct input_dev *ksu_touch_reader_dev;
static u32 ksu_touch_reader_index = (u32)-1;
static bool ksu_touch_reader_opened;
static bool ksu_touch_reader_handler_registered;
static bool ksu_touch_reader_dropped;
static u32 ksu_touch_reader_head;
static u32 ksu_touch_reader_tail;
static u32 ksu_touch_reader_count;
static u32 ksu_touch_reader_current_slot;
static u32 ksu_touch_reader_slot_count;
static s32 ksu_touch_reader_tracking_id[KSU_TOUCH_READER_MAX_SLOTS];
static s32 ksu_touch_reader_x[KSU_TOUCH_READER_MAX_SLOTS];
static s32 ksu_touch_reader_y[KSU_TOUCH_READER_MAX_SLOTS];
static s32 ksu_touch_reader_down[KSU_TOUCH_READER_MAX_SLOTS];
static struct ksu_touch_reader_event ksu_touch_reader_ring[KSU_TOUCH_RING_SIZE];

static bool ksu_input_dev_is_touchscreen(struct input_dev *dev)
{
	return dev &&
		test_bit(EV_ABS, dev->evbit) &&
		test_bit(ABS_MT_SLOT, dev->absbit) &&
		test_bit(ABS_MT_TRACKING_ID, dev->absbit) &&
		test_bit(ABS_MT_POSITION_X, dev->absbit) &&
		test_bit(ABS_MT_POSITION_Y, dev->absbit);
}

static void ksu_touch_reader_reset_locked(void)
{
	int i;

	ksu_touch_reader_head = 0;
	ksu_touch_reader_tail = 0;
	ksu_touch_reader_count = 0;
	ksu_touch_reader_dropped = false;
	ksu_touch_reader_current_slot = 0;
	for (i = 0; i < KSU_TOUCH_READER_MAX_SLOTS; i++) {
		ksu_touch_reader_tracking_id[i] = -1;
		ksu_touch_reader_x[i] = 0;
		ksu_touch_reader_y[i] = 0;
		ksu_touch_reader_down[i] = 0;
	}
}

static void ksu_touch_reader_push_locked(unsigned int type,
					 unsigned int code, int value)
{
	struct ksu_touch_reader_event *event;

	if (ksu_touch_reader_count >= KSU_TOUCH_RING_SIZE) {
		ksu_touch_reader_tail = (ksu_touch_reader_tail + 1) % KSU_TOUCH_RING_SIZE;
		ksu_touch_reader_count--;
		ksu_touch_reader_dropped = true;
	}

	event = &ksu_touch_reader_ring[ksu_touch_reader_head];
	event->type = type;
	event->code = code;
	event->value = value;
	ksu_touch_reader_head = (ksu_touch_reader_head + 1) % KSU_TOUCH_RING_SIZE;
	ksu_touch_reader_count++;
}

static void ksu_touch_reader_update_snapshot_locked(unsigned int type,
						   unsigned int code, int value)
{
	u32 slot;

	if (type != EV_ABS)
		return;

	if (code == ABS_MT_SLOT) {
		if (value < 0)
			value = 0;
		if (value >= KSU_TOUCH_READER_MAX_SLOTS)
			value = KSU_TOUCH_READER_MAX_SLOTS - 1;
		ksu_touch_reader_current_slot = value;
		return;
	}

	slot = ksu_touch_reader_current_slot;
	if (slot >= KSU_TOUCH_READER_MAX_SLOTS)
		return;

	switch (code) {
	case ABS_MT_TRACKING_ID:
		ksu_touch_reader_tracking_id[slot] = value;
		ksu_touch_reader_down[slot] = value >= 0 ? 1 : 0;
		break;
	case ABS_MT_POSITION_X:
		ksu_touch_reader_x[slot] = value;
		break;
	case ABS_MT_POSITION_Y:
		ksu_touch_reader_y[slot] = value;
		break;
	default:
		break;
	}
}

static void ksu_touch_reader_fill_snapshot_locked(struct ksu_touch_reader_cmd *cmd)
{
	int i;

	cmd->registered = ksu_touch_reader_handler_registered ? 1 : 0;
	cmd->index = ksu_touch_reader_index;
	cmd->current_slot = ksu_touch_reader_current_slot;
	cmd->slot_count = ksu_touch_reader_slot_count;
	for (i = 0; i < KSU_TOUCH_READER_MAX_SLOTS; i++) {
		cmd->tracking_id[i] = ksu_touch_reader_tracking_id[i];
		cmd->x[i] = ksu_touch_reader_x[i];
		cmd->y[i] = ksu_touch_reader_y[i];
		cmd->down[i] = ksu_touch_reader_down[i];
	}
}

static bool ksu_touch_reader_has_data(void)
{
	return READ_ONCE(ksu_touch_reader_count) > 0 ||
		READ_ONCE(ksu_touch_reader_dropped) ||
		!READ_ONCE(ksu_touch_reader_opened);
}

static void ksu_touch_reader_close_selected(void)
{
	struct input_dev *old_dev;
	unsigned long flags;

	spin_lock_irqsave(&ksu_touch_reader_lock, flags);
	old_dev = ksu_touch_reader_dev;
	ksu_touch_reader_dev = NULL;
	ksu_touch_reader_index = (u32)-1;
	ksu_touch_reader_opened = false;
	ksu_touch_reader_slot_count = 0;
	ksu_touch_reader_reset_locked();
	spin_unlock_irqrestore(&ksu_touch_reader_lock, flags);

	if (old_dev)
		input_put_device(old_dev);

	wake_up_interruptible(&ksu_touch_reader_wait);
}

static int ksu_touch_reader_open(u32 index)
{
	struct input_dev *idev;
	unsigned long flags;
	u32 slot_count = KSU_TOUCH_READER_MAX_SLOTS;

	idev = ksu_find_input_dev_by_index(index);
	if (!idev)
		return -ENODEV;

	if (!ksu_input_dev_is_touchscreen(idev)) {
		input_put_device(idev);
		return -EINVAL;
	}

	if (idev->mt && idev->mt->num_slots > 0)
		slot_count = min_t(u32, idev->mt->num_slots, KSU_TOUCH_READER_MAX_SLOTS);

	mutex_lock(&ksu_touch_reader_mutex);
	ksu_touch_reader_close_selected();
	spin_lock_irqsave(&ksu_touch_reader_lock, flags);
	ksu_touch_reader_dev = idev;
	ksu_touch_reader_index = index;
	ksu_touch_reader_opened = true;
	ksu_touch_reader_slot_count = slot_count;
	ksu_touch_reader_reset_locked();
	spin_unlock_irqrestore(&ksu_touch_reader_lock, flags);
	mutex_unlock(&ksu_touch_reader_mutex);

	wake_up_interruptible(&ksu_touch_reader_wait);
	return 0;
}

static int ksu_touch_reader_read(struct ksu_touch_reader_cmd *cmd)
{
	u32 max_events;
	unsigned long flags;
	long wait_result;
	int err = 0;

	max_events = cmd->max_events;
	if (max_events > KSU_TOUCH_READER_MAX_EVENTS)
		max_events = KSU_TOUCH_READER_MAX_EVENTS;
	if (cmd->timeout_ms > 1000)
		cmd->timeout_ms = 1000;

	if (max_events > 0 && cmd->timeout_ms > 0) {
		wait_result = wait_event_interruptible_timeout(
			ksu_touch_reader_wait,
			ksu_touch_reader_has_data(),
			msecs_to_jiffies(cmd->timeout_ms));
		if (wait_result < 0)
			return wait_result;
	}

	spin_lock_irqsave(&ksu_touch_reader_lock, flags);
	if (!ksu_touch_reader_opened) {
		err = -ENODEV;
		goto out_unlock;
	}

	cmd->event_count = 0;
	while (cmd->event_count < max_events && ksu_touch_reader_count > 0) {
		cmd->events[cmd->event_count] = ksu_touch_reader_ring[ksu_touch_reader_tail];
		ksu_touch_reader_tail = (ksu_touch_reader_tail + 1) % KSU_TOUCH_RING_SIZE;
		ksu_touch_reader_count--;
		cmd->event_count++;
	}

	cmd->dropped = ksu_touch_reader_dropped ? 1 : 0;
	ksu_touch_reader_dropped = false;
	ksu_touch_reader_fill_snapshot_locked(cmd);

out_unlock:
	spin_unlock_irqrestore(&ksu_touch_reader_lock, flags);
	cmd->result = err;
	return err;
}

static int do_touch_reader(void __user *arg)
{
	struct ksu_touch_reader_cmd cmd;
	unsigned long flags;
	int err = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	cmd.result = 0;
	cmd.event_count = 0;
	cmd.dropped = 0;

	switch (cmd.op) {
	case KSU_TOUCH_READER_OPEN:
		err = ksu_touch_reader_open(cmd.index);
		break;
	case KSU_TOUCH_READER_READ:
		err = ksu_touch_reader_read(&cmd);
		break;
	case KSU_TOUCH_READER_CLOSE:
		mutex_lock(&ksu_touch_reader_mutex);
		ksu_touch_reader_close_selected();
		mutex_unlock(&ksu_touch_reader_mutex);
		break;
	case KSU_TOUCH_READER_STATUS:
		spin_lock_irqsave(&ksu_touch_reader_lock, flags);
		cmd.result = ksu_touch_reader_opened ? 1 : 0;
		ksu_touch_reader_fill_snapshot_locked(&cmd);
		spin_unlock_irqrestore(&ksu_touch_reader_lock, flags);
		break;
	default:
		err = -EINVAL;
		break;
	}

	if (err)
		cmd.result = err;

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return err;
}

static void ksu_touch_reader_event(struct input_handle *handle,
					   unsigned int type,
					   unsigned int code,
					   int value)
{
	unsigned long flags;
	bool should_wake = false;

	spin_lock_irqsave(&ksu_touch_reader_lock, flags);
	if (ksu_touch_reader_opened && handle->dev == ksu_touch_reader_dev) {
		ksu_touch_reader_update_snapshot_locked(type, code, value);
		ksu_touch_reader_push_locked(type, code, value);
		should_wake = true;
	}
	spin_unlock_irqrestore(&ksu_touch_reader_lock, flags);

	if (should_wake)
		wake_up_interruptible(&ksu_touch_reader_wait);
}

static int ksu_touch_reader_connect(struct input_handler *handler,
					    struct input_dev *dev,
					    const struct input_device_id *id)
{
	struct input_handle *handle;
	int err;

	if (!ksu_input_dev_is_touchscreen(dev))
		return -ENODEV;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "ksu_touch_reader";

	err = input_register_handle(handle);
	if (err)
		goto err_free;

	err = input_open_device(handle);
	if (err)
		goto err_unregister;

	return 0;

err_unregister:
	input_unregister_handle(handle);
err_free:
	kfree(handle);
	return err;
}

static void ksu_touch_reader_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id ksu_touch_reader_ids[] = {
	{ .driver_info = 1 },
	{ },
};

static struct input_handler ksu_touch_reader_handler = {
	.event = ksu_touch_reader_event,
	.connect = ksu_touch_reader_connect,
	.disconnect = ksu_touch_reader_disconnect,
	.name = "ksu_touch_reader",
	.id_table = ksu_touch_reader_ids,
};

static void ksu_touch_reader_register_handler(void)
{
	int err;

	if (ksu_touch_reader_handler_registered)
		return;

	err = input_register_handler(&ksu_touch_reader_handler);
	if (!err)
		ksu_touch_reader_handler_registered = true;
}

static void ksu_touch_reader_unregister_handler(void)
{
	if (!ksu_touch_reader_handler_registered)
		return;

	input_unregister_handler(&ksu_touch_reader_handler);
	ksu_touch_reader_handler_registered = false;
}

static atomic64_t ksu_volume_up_presses = ATOMIC64_INIT(0);
static atomic64_t ksu_volume_down_presses = ATOMIC64_INIT(0);
static bool ksu_volume_handler_registered;

static bool ksu_input_dev_has_volume_key(struct input_dev *dev)
{
	return dev &&
		test_bit(EV_KEY, dev->evbit) &&
		(test_bit(KEY_VOLUMEUP, dev->keybit) ||
		 test_bit(KEY_VOLUMEDOWN, dev->keybit));
}

static void ksu_volume_event(struct input_handle *handle,
			     unsigned int type,
			     unsigned int code,
			     int value)
{
	if (type != EV_KEY || value != 1)
		return;

	if (code == KEY_VOLUMEUP)
		atomic64_inc(&ksu_volume_up_presses);
	else if (code == KEY_VOLUMEDOWN)
		atomic64_inc(&ksu_volume_down_presses);
}

static int ksu_volume_connect(struct input_handler *handler,
			      struct input_dev *dev,
			      const struct input_device_id *id)
{
	struct input_handle *handle;
	int err;

	if (!ksu_input_dev_has_volume_key(dev))
		return -ENODEV;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "ksu_volume";

	err = input_register_handle(handle);
	if (err)
		goto err_free;

	err = input_open_device(handle);
	if (err)
		goto err_unregister;

	return 0;

err_unregister:
	input_unregister_handle(handle);
err_free:
	kfree(handle);
	return err;
}

static void ksu_volume_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id ksu_volume_ids[] = {
	{ .driver_info = 1 },
	{ },
};

static struct input_handler ksu_volume_handler = {
	.event = ksu_volume_event,
	.connect = ksu_volume_connect,
	.disconnect = ksu_volume_disconnect,
	.name = "ksu_volume",
	.id_table = ksu_volume_ids,
};

static void ksu_volume_register_handler(void)
{
	int err;

	if (ksu_volume_handler_registered)
		return;

	err = input_register_handler(&ksu_volume_handler);
	if (!err)
		ksu_volume_handler_registered = true;
}

static void ksu_volume_unregister_handler(void)
{
	if (!ksu_volume_handler_registered)
		return;

	input_unregister_handler(&ksu_volume_handler);
	ksu_volume_handler_registered = false;
}

static int do_volume_key_state(void __user *arg)
{
	struct ksu_volume_key_state_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.volume_up_presses = atomic64_read(&ksu_volume_up_presses);
	cmd.volume_down_presses = atomic64_read(&ksu_volume_down_presses);
	cmd.registered = ksu_volume_handler_registered ? 1 : 0;

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return 0;
}


static int do_process_signal(void __user *arg)
{
	struct ksu_process_signal_cmd cmd;
	struct pid *pid;
	int sig;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	if (cmd.pid <= 0)
		return -EINVAL;

	switch (cmd.op) {
	case KSU_PROCESS_SIGNAL_DIRECT:
		sig = cmd.signal;
		break;
	case KSU_PROCESS_SIGNAL_CHECK:
		sig = 0;
		break;
	case KSU_PROCESS_SIGNAL_STOP:
		sig = SIGSTOP;
		break;
	case KSU_PROCESS_SIGNAL_CONT:
		sig = SIGCONT;
		break;
	case KSU_PROCESS_SIGNAL_TERM:
		sig = SIGTERM;
		break;
	case KSU_PROCESS_SIGNAL_KILL:
		sig = SIGKILL;
		break;
	default:
		return -EINVAL;
	}

	if (!valid_signal(sig))
		return -EINVAL;

	pid = find_vpid(cmd.pid);
	if (!pid)
		return -ESRCH;

	ret = kill_pid(pid, sig, 1);
	cmd.signal = sig;
	cmd.result = ret;

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return ret;
}

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
    { .cmd = KSU_IOCTL_GRANT_ROOT,
      .name = "GRANT_ROOT",
      .handler = do_grant_root,
      .perm_check = allowed_for_su },
    { .cmd = KSU_IOCTL_GET_INFO,
      .name = "GET_INFO",
      .handler = do_get_info,
      .perm_check = always_allow },
    { .cmd = KSU_IOCTL_REPORT_EVENT,
      .name = "REPORT_EVENT",
      .handler = do_report_event,
      .perm_check = only_root },
    { .cmd = KSU_IOCTL_SET_SEPOLICY,
      .name = "SET_SEPOLICY",
      .handler = do_set_sepolicy,
      .perm_check = only_root },
    { .cmd = KSU_IOCTL_CHECK_SAFEMODE,
      .name = "CHECK_SAFEMODE",
      .handler = do_check_safemode,
      .perm_check = always_allow },
    { .cmd = KSU_IOCTL_GET_ALLOW_LIST,
      .name = "GET_ALLOW_LIST",
      .handler = do_get_allow_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_DENY_LIST,
      .name = "GET_DENY_LIST",
      .handler = do_get_deny_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_NEW_GET_ALLOW_LIST,
      .name = "NEW_GET_ALLOW_LIST",
      .handler = do_new_get_allow_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_NEW_GET_DENY_LIST,
      .name = "NEW_GET_DENY_LIST",
      .handler = do_new_get_deny_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_GRANTED_ROOT,
      .name = "UID_GRANTED_ROOT",
      .handler = do_uid_granted_root,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_SHOULD_UMOUNT,
      .name = "UID_SHOULD_UMOUNT",
      .handler = do_uid_should_umount,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_MANAGER_APPID,
      .name = "GET_MANAGER_APPID",
      .handler = do_get_manager_appid,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_APP_PROFILE,
      .name = "GET_APP_PROFILE",
      .handler = do_get_app_profile,
      .perm_check = only_manager },
    { .cmd = KSU_IOCTL_SET_APP_PROFILE,
      .name = "SET_APP_PROFILE",
      .handler = do_set_app_profile,
      .perm_check = only_manager },
    { .cmd = KSU_IOCTL_GET_FEATURE,
      .name = "GET_FEATURE",
      .handler = do_get_feature,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_SET_FEATURE,
      .name = "SET_FEATURE",
      .handler = do_set_feature,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_WRAPPER_FD,
      .name = "GET_WRAPPER_FD",
      .handler = do_get_wrapper_fd,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_MANAGE_MARK,
      .name = "MANAGE_MARK",
      .handler = do_manage_mark,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_NUKE_EXT4_SYSFS,
      .name = "NUKE_EXT4_SYSFS",
      .handler = do_nuke_ext4_sysfs,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_ADD_TRY_UMOUNT,
      .name = "ADD_TRY_UMOUNT",
      .handler = add_try_umount,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_MANAGE_PID_HIDE,
      .name = "MANAGE_PID_HIDE",
      .handler = do_manage_pid_hide,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_MEM_RW,
      .name = "MEM_RW",
      .handler = do_mem_rw,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_FIND_PID,
      .name = "FIND_PID",
      .handler = do_find_pid,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_QUERY_MODULE,
      .name = "QUERY_MODULE",
      .handler = do_query_module,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_INSTANCE_LOCK,
      .name = "INSTANCE_LOCK",
      .handler = do_instance_lock,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_OOM_SCORE_ADJ,
      .name = "OOM_SCORE_ADJ",
      .handler = do_oom_score_adj,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_QUERY_VMA,
      .name = "QUERY_VMA",
      .handler = do_query_vma,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_PROC_STATS,
      .name = "GET_PROC_STATS",
      .handler = do_get_proc_stats,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_INPUT_DEVICE_QUERY,
      .name = "INPUT_DEVICE_QUERY",
      .handler = do_input_device_query,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_PROCESS_SIGNAL,
      .name = "PROCESS_SIGNAL",
      .handler = do_process_signal,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_INPUT_INJECT,
      .name = "INPUT_INJECT",
      .handler = do_input_inject,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_VOLUME_KEY_STATE,
      .name = "VOLUME_KEY_STATE",
      .handler = do_volume_key_state,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_TOUCH_READER,
      .name = "TOUCH_READER",
      .handler = do_touch_reader,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_HOOK_MODE,
      .name = "GET_HOOK_MODE",
      .handler = do_get_hook_mode,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_VERSION_TAG,
      .name = "GET_VERSION_TAG",
      .handler = do_get_version_tag,
      .perm_check = manager_or_root },
    { .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL }
};

struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw =
        container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();
    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
		close_fd(fd);
#else
		ksys_close(fd);
#endif
	}

	kfree(tw);
}

static inline bool ksu_require_root(void)
{
	return current_uid().val == 0;
}

// copy to userspace (reply back)
static inline void ksu_copy_reply_user(unsigned long user_ptr, unsigned long reply)
{
	if (copy_to_user((void __user *)user_ptr, &reply, sizeof(reply)))
		pr_info("sys_reboot: reply fail\n");
}

#ifndef CONFIG_KSU_SUSFS
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;
	unsigned long user_ptr = reply;

	/* Check if this is a request to install KSU fd */
	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;

		tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
		if (!tw)
			return 0;

		tw->outp = (int __user *)arg4;
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_warn("install fd add task_work failed\n");
		}
	}

	if (magic2 == CHANGE_MANAGER_UID) {
		/* only root is allowed for this command */
		if (!ksu_require_root())
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid())
			ksu_copy_reply_user(user_ptr, reply);

		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {
		if (!ksu_require_root())
			return 0;

		int ret = send_sulog_dump((void __user *)arg4);
		if (ret)
			return 0;

		ksu_copy_reply_user(user_ptr, reply);
		return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		if (!ksu_require_root())
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		ksu_copy_reply_user(user_ptr, reply);
		return 0;
	}

	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command 
		if (!ksu_require_root())
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		// arg4 corresponds to *ppptr in the snippet
		if (copy_from_user(&u_pptr, (void __user *)arg4, sizeof(u_pptr)))
			return 0;

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
			strncpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strncpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
		strncpy(u->release, release_buf, sizeof(u->release));
		strncpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		ksu_copy_reply_user(user_ptr, reply);
		return 0;
	}

	return 0;
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};
#else
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
	// User's pointer -> reply
	unsigned long reply = (unsigned long)(*arg);
	unsigned long user_ptr = reply;

	if (magic1 != KSU_INSTALL_MAGIC1) {
		return -EINVAL;
	}

    // If magic2 is susfs and current process is root
    if (magic2 == SUSFS_MAGIC && ksu_require_root()) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
        if (cmd == CMD_SUSFS_ADD_SUS_PATH) {
            susfs_add_sus_path(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_ADD_SUS_PATH_LOOP) {
            susfs_add_sus_path_loop(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
        if (cmd == CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS) {
	        susfs_set_hide_sus_mnts_for_non_su_procs(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
        if (cmd == CMD_SUSFS_ADD_SUS_KSTAT) {
            susfs_add_sus_kstat(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_UPDATE_SUS_KSTAT) {
            susfs_update_sus_kstat(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
            susfs_add_sus_kstat(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
        if (cmd == CMD_SUSFS_SET_UNAME) {
            susfs_set_uname(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
        if (cmd == CMD_SUSFS_ENABLE_LOG) {
            susfs_enable_log(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
        if (cmd == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
            susfs_set_cmdline_or_bootconfig(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
        if (cmd == CMD_SUSFS_ADD_OPEN_REDIRECT) {
            susfs_add_open_redirect(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
        if (cmd == CMD_SUSFS_ADD_SUS_MAP) {
            susfs_add_sus_map(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP
        if (cmd == CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING) {
            susfs_set_avc_log_spoofing(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
            susfs_get_enabled_features(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_SHOW_VARIANT) {
            susfs_show_variant(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_SHOW_VERSION) {
            susfs_show_version(arg);
            return 0;
        }
        return -EINVAL;
    }

    // Check if this is a request to install KSU fd
    if (magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw)
            return 0;

        tw->outp = (int __user *)(*arg);
        tw->cb.func = ksu_install_fd_tw_func;

        if (task_work_add(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            pr_warn("install fd add task_work failed\n");
        }
		return 0;
    }

	if (magic2 == CHANGE_MANAGER_UID) {
		/* only root is allowed for this command */
		if (!ksu_require_root())
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid())
			ksu_copy_reply_user(user_ptr, reply);

		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {
		if (!ksu_require_root())
			return 0;

		int ret = send_sulog_dump((void __user *)*arg);
		if (ret)
			return 0;

		ksu_copy_reply_user(user_ptr, reply);
		return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		if (!ksu_require_root())
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		ksu_copy_reply_user(user_ptr, reply);
		return 0;
	}

	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command 
		if (!ksu_require_root())
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		// *arg is the user pointer value
		if (copy_from_user(&u_pptr, (void __user *)(*arg), sizeof(u_pptr)))
			return 0;

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
			strncpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strncpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
		strncpy(u->release, release_buf, sizeof(u->release));
		strncpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		ksu_copy_reply_user(user_ptr, reply);
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(ksu_handle_sys_reboot); // required visiblity for toolkit
#endif // #ifndef CONFIG_KSU_SUSFS

void ksu_supercalls_init(void)
{
	int i;

    pr_info("KernelSU IOCTL Commands:\n");
    for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
        pr_info("  %-18s = 0x%08x\n", ksu_ioctl_handlers[i].name,
                ksu_ioctl_handlers[i].cmd);
    }

#ifndef CONFIG_KSU_SUSFS
	int rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_info("reboot kprobe registered successfully\n");
	}
#endif // #ifndef CONFIG_KSU_SUSFS
    sulog_init_heap(); // grab heap memory
    ksu_volume_register_handler();
    ksu_touch_reader_register_handler();
}

void ksu_supercalls_exit(void)
{
    ksu_touch_reader_unregister_handler();
    ksu_volume_unregister_handler();
    mutex_lock(&ksu_touch_reader_mutex);
    ksu_touch_reader_close_selected();
    mutex_unlock(&ksu_touch_reader_mutex);
    mutex_lock(&ksu_input_inject_mutex);
    ksu_input_inject_close_locked();
    mutex_unlock(&ksu_input_inject_mutex);

#ifndef CONFIG_KSU_SUSFS
    unregister_kprobe(&reboot_kp);
#else
    pr_info("susfs: do nothing\n");
#endif // #ifndef CONFIG_KSU_SUSFS
}

// IOCTL dispatcher
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd,
                           unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int i;

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu ioctl: cmd=0x%x from uid=%d\n", cmd, current_uid().val);
#endif

    for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
        if (cmd == ksu_ioctl_handlers[i].cmd) {
            // Check permission first
            if (ksu_ioctl_handlers[i].perm_check &&
                !ksu_ioctl_handlers[i].perm_check()) {
                pr_warn("ksu ioctl: permission denied for cmd=0x%x uid=%d\n",
                        cmd, current_uid().val);
                return -EPERM;
            }
            // Execute handler
            return ksu_ioctl_handlers[i].handler(argp);
        }
    }

	pr_warn("ksu ioctl: unsupported command 0x%x\n", cmd);
	return -ENOTTY;
}

// File release handler
static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_info("ksu fd released\n");
	return 0;
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

    // Create anonymous inode file
    filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL,
                              O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}
