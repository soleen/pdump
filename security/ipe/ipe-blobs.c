// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-engine.h"
#include "ipe-blobs.h"

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/device-mapper.h>

/**
 * ipe_bdev_alloc_security: Performs the initialization of IPE's security blob.
 * @bdev: The block device to source the security blob from.
 *
 * The allocation is performed earlier by the LSM infrastructure,
 * (on behalf of all LSMs) in lsm_alloc_bdev. This memory should be
 * zero-initialized by the LSM infrastructure.
 *
 * Return:
 * 0 - OK
 */
int ipe_bdev_alloc_security(struct block_device *bdev)
{
	return 0;
}

/**
 * ipe_bdev_free_security: Frees all fields of IPE's block dev security blob.
 * @bdev: The block device to source the security blob from.
 *
 * The deallocation of the blob itself is performed later by the LSM
 * infrastructure, (on behalf of all LSMs) in lsm_free_bdev.
 *
 * Pointers allocated by the bdev_setsecurity hook and alloc_security
 * hook need to be deallocated here.
 */
void ipe_bdev_free_security(struct block_device *bdev)
{
	struct ipe_bdev_blob *bdev_sec = ipe_bdev(bdev);

	kfree(bdev_sec->dmverity_rh_sig);
	kfree(bdev_sec->dmverity_rh);

	memset(bdev_sec, 0x0, sizeof(*bdev_sec));
}

/**
 * ipe_bdev_setsecurity: Sets the a certain field of a block device security
 *			 blob, based on @key.
 * @bdev: The block device to source the security blob from.
 * @key: The key representing the information to be stored.
 * @value: The value to be stored.
 * @len: The length of @value.
 *
 * As block-devices are a generic implementation across specific stacks,
 * this allows information to be stored from various stacks.
 *
 * Return:
 * 0 - OK
 * !0 - Error
 */
int ipe_bdev_setsecurity(struct block_device *bdev, const char *key,
			 const void *value, size_t len)
{
	struct ipe_bdev_blob *bdev_sec = ipe_bdev(bdev);

	if (!strcmp(key, DM_VERITY_SIGNATURE_SEC_NAME)) {
		bdev_sec->dmverity_rh_sig = kmemdup(value, len, GFP_KERNEL);
		if (!bdev_sec->dmverity_rh_sig)
			return -ENOMEM;

		bdev_sec->dmv_rh_sig_len = len;

		return 0;
	}

	if (!strcmp(key, DM_VERITY_ROOTHASH_SEC_NAME)) {
		bdev_sec->dmverity_rh = kmemdup(value, len, GFP_KERNEL);
		if (!bdev_sec->dmverity_rh)
			return -ENOMEM;

		bdev_sec->rh_size = len;

		return 0;
	}

	return -ENOSYS;
}

/**
 * ipe_file_free_security: Frees all fields of IPE's file security blob.
 * @f: The file structure to source the security blob from.
 *
 * The deallocation of the blob itself is performed later by the LSM
 * infrastructure, (on behalf of all LSMs) in lsm_free_file.
 *
 */
void ipe_file_free_security(struct file *f)
{
	struct ipe_file_blob *file_sec = ipe_file(f);

	kfree(file_sec->app_path);

	memset(file_sec, 0x0, sizeof(*file_sec));
}

/**
 * ipe_file_set_userspace_pathname: Allocates a copy of the application provided
 *				    file path into the file security blob.
 * @f: The file structure to source the security blob from.
 * @path: the filename structure to obtain the application path from.
 *
 * The deallocation of the copy is performed in ipe_file_free_security.
 *
 * Return:
 * 0 - OK
 * -ENOMEM - Out of Memory
 */
int ipe_file_set_userspace_pathname(struct file *f, const struct filename *path)
{
	struct ipe_file_blob *file_sec = ipe_file(f);

	file_sec->app_path = kstrdup(path->name, GFP_KERNEL);
	if (!file_sec->app_path)
		return -ENOMEM;

	return 0;
}
