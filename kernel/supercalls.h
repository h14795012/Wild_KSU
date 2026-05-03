#ifndef __KSU_H_SUPERCALLS
#define __KSU_H_SUPERCALLS

#include <linux/types.h>
#include <linux/ioctl.h>
#include "app_profile.h"

// Magic numbers for reboot hook to install fd
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

// Toolkit extensions
#define CHANGE_MANAGER_UID 10006
#define KSU_UMOUNT_GETSIZE 107
#define KSU_UMOUNT_GETLIST 108
#define GET_SULOG_DUMP_V2 10010
#define CHANGE_KSUVER 10011
#define CHANGE_SPOOF_UNAME 10012

// Command structures for ioctl

struct ksu_become_daemon_cmd {
	__u8 token[65]; // Input: daemon token (null-terminated)
};

#define KSU_GET_INFO_FLAG_LKM (1U << 0)
#define KSU_GET_INFO_FLAG_MANAGER (1U << 1)
#define KSU_GET_INFO_FLAG_LATE_LOAD (1U << 2)

struct ksu_get_info_cmd {
	__u32 version; // Output: KERNEL_SU_VERSION
	__u32 flags; // Output: KSU_GET_INFO_FLAG_* bits
	__u32 features; // Output: max feature ID supported
};

struct ksu_report_event_cmd {
	__u32 event; // Input: EVENT_POST_FS_DATA, EVENT_BOOT_COMPLETED, etc.
};

struct ksu_set_sepolicy_cmd {
	__u64 data_len; // Input: bytes of serialized command payload
	__aligned_u64 data; // Input: pointer to serialized payload
};

struct ksu_sepolicy_cmd_hdr {
    __u32 cmd; // Input: command type, CMD_*
    __u32 subcmd; // Input: command subtype
};
// After each ksu_sepolicy_cmd_hdr, command arguments are encoded sequentially as:
// [u32 len][len bytes][\0], where len excludes the trailing '\0'.
// len == 0 represents ALL.
// Argument count is derived from cmd:
// CMD_NORMAL_PERM=4, CMD_XPERM=5, CMD_TYPE_STATE=1, CMD_TYPE=2,
// CMD_TYPE_ATTR=2, CMD_ATTR=1, CMD_TYPE_TRANSITION=5,
// CMD_TYPE_CHANGE=4, CMD_GENFSCON=3.

struct ksu_check_safemode_cmd {
	__u8 in_safe_mode; // Output: true if in safe mode, false otherwise
};

// deprecated
struct ksu_get_allow_list_cmd {
	__u32 uids[128]; // Output: array of allowed/denied UIDs
	__u32 count; // Output: number of UIDs in array
	__u8 allow; // Input: true for allow list, false for deny list
};

struct ksu_new_get_allow_list_cmd {
	__u16 count; // Input / Output: number of UIDs in array
	__u16 total_count; // Output: total number of UIDs in requested list
	__u32 uids[0]; // Output: array of allowed/denied UIDs
};

struct ksu_uid_granted_root_cmd {
	__u32 uid; // Input: target UID to check
	__u8 granted; // Output: true if granted, false otherwise
};

struct ksu_uid_should_umount_cmd {
	__u32 uid; // Input: target UID to check
	__u8 should_umount; // Output: true if should umount, false otherwise
};

struct ksu_get_manager_appid_cmd {
	__u32 appid; // Output: manager app id
};

struct ksu_get_app_profile_cmd {
	struct app_profile profile; // Input/Output: app profile structure
};

struct ksu_set_app_profile_cmd {
	struct app_profile profile; // Input: app profile structure
};

struct ksu_get_feature_cmd {
	__u32 feature_id; // Input: feature ID (enum ksu_feature_id)
	__u64 value; // Output: feature value/state
	__u8 supported; // Output: true if feature is supported, false otherwise
};

struct ksu_set_feature_cmd {
	__u32 feature_id; // Input: feature ID (enum ksu_feature_id)
	__u64 value; // Input: feature value/state to set
};

struct ksu_get_wrapper_fd_cmd {
	__u32 fd; // Input: userspace fd
	__u32 flags; // Input: flags of userspace fd
};

struct ksu_manage_mark_cmd {
	__u32 operation; // Input: KSU_MARK_*
	__s32 pid; // Input: target pid (0 for all processes)
	__u32 result; // Output: for get operation - mark status or reg_count
};

struct ksu_get_hook_mode_cmd {
	char mode[16];
};

struct ksu_get_version_tag_cmd {
	char tag[32];
};

#define KSU_MARK_GET 1
#define KSU_MARK_MARK 2
#define KSU_MARK_UNMARK 3
#define KSU_MARK_REFRESH 4

struct ksu_nuke_ext4_sysfs_cmd {
    __aligned_u64 arg; // Input: mnt pointer
};

struct ksu_add_try_umount_cmd {
    __aligned_u64 arg; // char ptr, this is the mountpoint
    __u32 flags; // this is the flag we use for it
    __u8 mode; // denotes what to do with it 0:wipe_list 1:add_to_list 2:delete_entry
};

#define KSU_UMOUNT_WIPE 0 // ignore everything and wipe list
#define KSU_UMOUNT_ADD 1 // add entry (path + flags)
#define KSU_UMOUNT_DEL 2 // delete entry, strcmp

struct ksu_manage_pid_hide_cmd {
    __s32 pid;
    __u8 hide; // 1 for hide, 0 for show
};

struct ksu_mem_rw_cmd {
    __s32 pid;
    __u32 _pad;
    __u64 addr;
    __u64 buf; // user space buffer pointer
    __u32 len;
    __u8 write; // 1 for write, 0 for read
};

struct ksu_find_pid_cmd {
    char process_name[256];
    __s32 pid;
};

struct ksu_query_module_cmd {
    __s32 pid;
    __u32 found;
    char module_name[128];
    __u64 base;
    __u64 end;
    __u64 size;
};

struct ksu_instance_lock_cmd {
    __u32 op; // 1: acquire, 0: release
};

#define KSU_OOM_SCORE_ADJ_GET 0
#define KSU_OOM_SCORE_ADJ_SET 1

struct ksu_oom_score_adj_cmd {
    __s32 pid;
    __s32 oom_score_adj;
    __u32 op; // KSU_OOM_SCORE_ADJ_*
    __u32 result;
};

#define KSU_QUERY_VMA_MODULE_BASE      0
#define KSU_QUERY_VMA_MEM_REGION       1
#define KSU_QUERY_VMA_MODULE_REGION    2
#define KSU_QUERY_VMA_MODULE_BSS       3
#define KSU_QUERY_VMA_MODULE_ANON_BSS  4
#define KSU_QUERY_VMA_CLUSTER_SEGMENT  5
#define KSU_QUERY_VMA_BY_INDEX         6
#define KSU_QUERY_VMA_COUNT            7

#define KSU_QUERY_VMA_FLAG_NAMED       0x00000001ULL
#define KSU_QUERY_VMA_FLAG_ANON_BSS    0x00000002ULL

struct ksu_query_vma_cmd {
    __s32 pid;
    __u32 type;
    __u32 index;
    __u32 found;
    char name[256];
    __u64 addr;
    __u64 base;
    __u64 end;
    __u64 size;
    __u64 offset;
    __u64 prot;
    __u64 flags;
};

struct ksu_proc_stats_cmd {
    __s32 pid;
    __u32 threads;
    __u64 rss;
    __u64 vmsize;
    __u32 fd_count;
    __s32 oom_score_adj;
};

struct ksu_input_device_query_cmd {
    __u32 index;
    __u32 found;
    char path[64];
    char name[128];
    __u32 bustype;
    __u32 vendor;
    __u32 product;
    __u32 version;
    __s32 abs_x_min;
    __s32 abs_x_max;
    __s32 abs_y_min;
    __s32 abs_y_max;
    __s32 mt_x_min;
    __s32 mt_x_max;
    __s32 mt_y_min;
    __s32 mt_y_max;
    __u32 slot_count;
    __u32 is_direct;
    __u32 is_pointer;
    __u32 has_btn_touch;
    __u32 has_btn_tool_finger;
    __u32 has_mt_slot;
    __u32 has_mt_tracking_id;
    __u32 has_mt_position;
    __u32 has_mt_pressure;
    __u32 has_mt_touch_major;
    __u32 has_mt_width_major;
    __u32 has_abs_x;
    __u32 has_abs_y;
    __s32 pressure_min;
    __s32 pressure_max;
    __s32 tracking_id_min;
    __s32 tracking_id_max;
};

#define KSU_INPUT_INJECT_OPEN   0
#define KSU_INPUT_INJECT_EVENT  1
#define KSU_INPUT_INJECT_CLOSE  2
#define KSU_INPUT_INJECT_STATUS 3

struct ksu_input_inject_cmd {
    __u32 op;
    __u32 index;
    __u32 type;
    __u32 code;
    __s32 value;
    __s32 result;
};

#define KSU_TOUCH_READER_MAX_EVENTS 128
#define KSU_TOUCH_READER_MAX_SLOTS  10

#define KSU_TOUCH_READER_OPEN   0
#define KSU_TOUCH_READER_READ   1
#define KSU_TOUCH_READER_CLOSE  2
#define KSU_TOUCH_READER_STATUS 3

struct ksu_touch_reader_event {
    __u32 type;
    __u32 code;
    __s32 value;
};

struct ksu_touch_reader_cmd {
    __u32 op;
    __u32 index;
    __u32 max_events;
    __u32 event_count;
    __u32 timeout_ms;
    __s32 result;
    __u32 dropped;
    __u32 registered;
    __u32 current_slot;
    __u32 slot_count;
    __s32 tracking_id[KSU_TOUCH_READER_MAX_SLOTS];
    __s32 x[KSU_TOUCH_READER_MAX_SLOTS];
    __s32 y[KSU_TOUCH_READER_MAX_SLOTS];
    __s32 down[KSU_TOUCH_READER_MAX_SLOTS];
    struct ksu_touch_reader_event events[KSU_TOUCH_READER_MAX_EVENTS];
};

struct ksu_volume_key_state_cmd {
    __u64 volume_up_presses;
    __u64 volume_down_presses;
    __u32 registered;
    __u32 reserved;
};

#define KSU_PROCESS_SIGNAL_DIRECT 0
#define KSU_PROCESS_SIGNAL_CHECK  1
#define KSU_PROCESS_SIGNAL_STOP   2
#define KSU_PROCESS_SIGNAL_CONT   3
#define KSU_PROCESS_SIGNAL_TERM   4
#define KSU_PROCESS_SIGNAL_KILL   5

struct ksu_process_signal_cmd {
    __s32 pid;
    __s32 signal;
    __u32 op;
    __s32 result;
};

// IOCTL command definitions
#define KSU_IOCTL_GRANT_ROOT _IOC(_IOC_NONE, 'K', 1, 0)
#define KSU_IOCTL_GET_INFO _IOC(_IOC_READ, 'K', 2, 0)
#define KSU_IOCTL_REPORT_EVENT _IOC(_IOC_WRITE, 'K', 3, 0)
#define KSU_IOCTL_SET_SEPOLICY _IOC(_IOC_READ | _IOC_WRITE, 'K', 4, 0)
#define KSU_IOCTL_CHECK_SAFEMODE _IOC(_IOC_READ, 'K', 5, 0)
// deprecated
#define KSU_IOCTL_GET_ALLOW_LIST _IOC(_IOC_READ | _IOC_WRITE, 'K', 6, 0)
// deprecated
#define KSU_IOCTL_GET_DENY_LIST _IOC(_IOC_READ | _IOC_WRITE, 'K', 7, 0)
#define KSU_IOCTL_NEW_GET_ALLOW_LIST                                      \
	_IOWR('K', 6, struct ksu_new_get_allow_list_cmd)
#define KSU_IOCTL_NEW_GET_DENY_LIST                                       \
	_IOWR('K', 7, struct ksu_new_get_allow_list_cmd)
#define KSU_IOCTL_UID_GRANTED_ROOT _IOC(_IOC_READ | _IOC_WRITE, 'K', 8, 0)
#define KSU_IOCTL_UID_SHOULD_UMOUNT _IOC(_IOC_READ | _IOC_WRITE, 'K', 9, 0)
#define KSU_IOCTL_GET_MANAGER_APPID _IOC(_IOC_READ, 'K', 10, 0)
#define KSU_IOCTL_GET_APP_PROFILE _IOC(_IOC_READ | _IOC_WRITE, 'K', 11, 0)
#define KSU_IOCTL_SET_APP_PROFILE _IOC(_IOC_WRITE, 'K', 12, 0)
#define KSU_IOCTL_GET_FEATURE _IOC(_IOC_READ | _IOC_WRITE, 'K', 13, 0)
#define KSU_IOCTL_SET_FEATURE _IOC(_IOC_WRITE, 'K', 14, 0)
#define KSU_IOCTL_GET_WRAPPER_FD _IOC(_IOC_WRITE, 'K', 15, 0)
#define KSU_IOCTL_MANAGE_MARK _IOC(_IOC_READ | _IOC_WRITE, 'K', 16, 0)
#define KSU_IOCTL_NUKE_EXT4_SYSFS _IOC(_IOC_WRITE, 'K', 17, 0)
#define KSU_IOCTL_ADD_TRY_UMOUNT _IOC(_IOC_WRITE, 'K', 18, 0)
#define KSU_IOCTL_MANAGE_PID_HIDE _IOW('K', 20, struct ksu_manage_pid_hide_cmd)
#define KSU_IOCTL_MEM_RW _IOWR('K', 21, struct ksu_mem_rw_cmd)
#define KSU_IOCTL_FIND_PID _IOWR('K', 22, struct ksu_find_pid_cmd)
#define KSU_IOCTL_QUERY_MODULE _IOWR('K', 23, struct ksu_query_module_cmd)
#define KSU_IOCTL_INSTANCE_LOCK _IOWR('K', 24, struct ksu_instance_lock_cmd)
#define KSU_IOCTL_OOM_SCORE_ADJ _IOWR('K', 25, struct ksu_oom_score_adj_cmd)
#define KSU_IOCTL_QUERY_VMA _IOWR('K', 26, struct ksu_query_vma_cmd)
#define KSU_IOCTL_GET_PROC_STATS _IOWR('K', 27, struct ksu_proc_stats_cmd)
#define KSU_IOCTL_INPUT_DEVICE_QUERY _IOWR('K', 28, struct ksu_input_device_query_cmd)
#define KSU_IOCTL_PROCESS_SIGNAL _IOWR('K', 29, struct ksu_process_signal_cmd)
#define KSU_IOCTL_INPUT_INJECT _IOWR('K', 30, struct ksu_input_inject_cmd)
#define KSU_IOCTL_VOLUME_KEY_STATE _IOWR('K', 31, struct ksu_volume_key_state_cmd)
#define KSU_IOCTL_TOUCH_READER _IOWR('K', 32, struct ksu_touch_reader_cmd)
#define KSU_IOCTL_GET_HOOK_MODE _IOC(_IOC_READ, 'K', 98, 0)
#define KSU_IOCTL_GET_VERSION_TAG _IOC(_IOC_READ, 'K', 99, 0)

// IOCTL handler types
typedef int (*ksu_ioctl_handler_t)(void __user *arg);
typedef bool (*ksu_perm_check_t)(void);

// IOCTL command mapping
struct ksu_ioctl_cmd_map {
	unsigned int cmd;
	const char *name;
	ksu_ioctl_handler_t handler;
	ksu_perm_check_t perm_check; // Permission check function
};

// Install KSU fd to current process
int ksu_install_fd(void);

void ksu_supercalls_init(void);
void ksu_supercalls_exit(void);
#endif // __KSU_H_SUPERCALLS
