#ifndef __WKSU_FREEZE_H
#define __WKSU_FREEZE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/ptrace.h>

#define WKSU_HOLD_MAX_FIELDS 8
#define WKSU_HOLD_FIELD_SIZE 64

struct wksu_hold_field {
    __u64 addr;
    __u32 len;
};

struct wksu_hold_snapshot {
    struct user_pt_regs regs;
    __u64 tls;
    __u64 sample_ns;
    __u32 nr;
    __u32 len[WKSU_HOLD_MAX_FIELDS];
    __u8  data[WKSU_HOLD_MAX_FIELDS][WKSU_HOLD_FIELD_SIZE];
};

int wksu_capture_consistent_snapshot(struct task_struct *target,
                                    struct mm_struct *mm,
                                    const struct wksu_hold_field *fields,
                                    __u32 nr,
                                    struct wksu_hold_snapshot *out,
                                    __u32 timeout_us,
                                    __u32 lease_us);

#endif /* __WKSU_FREEZE_H */
