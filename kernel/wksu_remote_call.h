#ifndef __WKSU_REMOTE_CALL_H
#define __WKSU_REMOTE_CALL_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include "supercalls.h"

int wksu_execute_remote_call(struct task_struct *target,
                            struct mm_struct *mm,
                            struct wksu_remote_call_cmd *cmd);

int wksu_remote_call_init(void);
void wksu_remote_call_exit(void);

#endif /* __WKSU_REMOTE_CALL_H */
