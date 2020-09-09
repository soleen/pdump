// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-policy.h"
#include "ipe-hooks.h"
#include "properties/prop-entry.h"

#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/security.h>

static struct security_hook_list ipe_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ipe_on_exec),
	LSM_HOOK_INIT(mmap_file, ipe_on_mmap),
	LSM_HOOK_INIT(kernel_read_file, ipe_on_kernel_read),
	LSM_HOOK_INIT(kernel_load_data, ipe_on_kernel_load_data),
	LSM_HOOK_INIT(file_mprotect, ipe_on_mprotect),
	LSM_HOOK_INIT(sb_free_security, ipe_sb_free_security),
	LSM_HOOK_INIT(bdev_alloc_security, ipe_bdev_alloc_security),
	LSM_HOOK_INIT(bdev_free_security, ipe_bdev_free_security),
	LSM_HOOK_INIT(bdev_setsecurity, ipe_bdev_setsecurity),
	LSM_HOOK_INIT(file_open, ipe_file_open),
	LSM_HOOK_INIT(file_free_security, ipe_file_free_security),
};

/**
 * ipe_load_properties: Call the property entry points for all the IPE modules
 *			that were selected at kernel build-time.
 *
 * Return:
 * 0 - OK
 */
static int __init ipe_load_properties(void)
{
	int rc = 0;

	rc = ipe_init_bootv();
	if (rc != 0)
		return rc;

	rc = ipe_init_dm_verity_signature();
	if (rc != 0)
		return rc;

	rc = ipe_init_dm_verity_rh();
	if (rc != 0)
		return rc;

	return rc;
}

/**
 * ipe_init: Entry point of IPE.
 *
 * This is called at LSM init, which happens occurs early during kernel
 * start up. During this phase, IPE loads the
 * properties compiled into the kernel, and register's IPE's hooks.
 * The boot policy is loaded later, during securityfs init, at which point
 * IPE will start enforcing its policy.
 *
 * Return:
 * 0 - OK
 * -ENOMEM - sysctl registration failed.
 */
static int __init ipe_init(void)
{
	int rc;

	rc = ipe_load_properties();
	if (rc != 0)
		panic("IPE: properties failed to load");

	pr_info("mode=%s", (ipe_enforce == 1) ? IPE_MODE_ENFORCE :
						IPE_MODE_PERMISSIVE);

	security_add_hooks(ipe_hooks, ARRAY_SIZE(ipe_hooks), "IPE");

	return rc;
}

struct lsm_blob_sizes ipe_blobs __lsm_ro_after_init = {
	.lbs_cred = 0,
	.lbs_file = sizeof(struct ipe_file_blob),
	.lbs_inode = 0,
	.lbs_ipc = 0,
	.lbs_msg_msg = 0,
	.lbs_task = 0,
	.lbs_bdev = sizeof(struct ipe_bdev_blob),
};

DEFINE_LSM(ipe) = {
	.name = "ipe",
	.init = ipe_init,
	.blobs = &ipe_blobs,
};

bool ipe_enforce = true;
bool ipe_success_audit;

#ifdef CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH

/* Module Parameter for Default Behavior on Boot */
module_param_named(enforce, ipe_enforce, bool, 0644);
MODULE_PARM_DESC(enforce, "IPE Permissive Switch");

#endif /* CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH */

/* Module Parameter for Success Audit on Boot */
module_param_named(success_audit, ipe_success_audit, bool, 0644);
MODULE_PARM_DESC(success_audit, "IPE Audit on Success");
