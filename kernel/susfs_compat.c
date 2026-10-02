#include <linux/types.h>
#include <linux/jump_label.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include "security.h"

/*
 * Compatibility stubs for SUSFS manual hooks in common kernel (GKI 5.10).
 * These symbols are referenced by 50_add_susfs_in_gki-*.patch in:
 *   - fs/exec.c
 *   - security/selinux/hooks.c
 *   - security/selinux/selinuxfs.c
 *   - security/selinux/ss/services.c
 */

/* 1. Static keys */
DEFINE_STATIC_KEY_TRUE(ksu_is_init_rc_hook_enabled);
DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);
DEFINE_STATIC_KEY_TRUE(ksu_is_input_hook_enabled);

/* 2. SELinux fake state & status stubs */
struct selinux_state fake_state;
struct page *fake_status = NULL;
bool ksu_selinux_hide_running __read_mostly = false;
bool ksu_selinux_hide_enabled __read_mostly = false;

void initialize_fake_status(void)
{
    /* No-op stub for minimal Wild_KSU runtime */
}

/* 3. Post-execveat sucompat stub */
int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr,
                                      void *argv_user, void *envp_user,
                                      int *__never_use_flags, int *retval)
{
    return 0;
}

/* 4. Weak fallback for susfs_run_sus_path_loop */
void __attribute__((weak)) susfs_run_sus_path_loop(void)
{
}
