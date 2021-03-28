// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-parse.h"
#include "ipe-secfs.h"
#include "ipe-policy.h"
#include "ipe-audit.h"

#include <linux/types.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/verification.h>
#include <linux/capability.h>

#define IPE_ROOT		"ipe"
#define IPE_POLICIES		"policies"
#define NEW_POLICY		"new_policy"
#define IPE_PROPERTY_CFG	"property_config"
#define IPE_SUCCESS_AUDIT	"success_audit"
#define IPE_ENFORCE		"enforce"

#define IPE_FULL_CONTENT	"raw"
#define IPE_INNER_CONTENT	"content"
#define IPE_ACTIVE_POLICY	"active"
#define IPE_DELETE_POLICY	"delete"

struct ipe_policy_node {
	u8		*data;
	size_t		data_len;
	const u8	*content;
	size_t		content_size;

	struct ipe_policy *parsed;
};

/* root directory */
static struct dentry *securityfs_root __ro_after_init;

/* subdirectory containing policies */
static struct dentry *policies_root __ro_after_init;

/* boot policy */
static struct dentry *boot_policy_node __ro_after_init;

/* top-level IPE commands */
static struct dentry *new_policy_node __ro_after_init;
static struct dentry *property_cfg_node __ro_after_init;
static struct dentry *enforce_node __ro_after_init;
static struct dentry *success_audit_node __ro_after_init;

/* lock for synchronizing writers across ipe policy */
DEFINE_MUTEX(ipe_policy_lock);

/**
 * get_int_user - retrieve a single integer from a string located in userspace.
 * @data: usespace address to parse for an integer
 * @len: length of @data
 * @offset: offset into @data. Unused.
 * @value: pointer to a value to propagate with the result
 *
 * Return:
 * 0 - OK
 * -ENOMEM - allocation failed
 * -EINVAL - more than 1 integer was present
 * Other - see strnpy_from_user
 */
static int get_int_user(const char __user *data, size_t len, loff_t *offset,
			int *value)
{
	int rc = 0;
	char *buffer = NULL;

	buffer = kzalloc(len + 1, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	rc = strncpy_from_user(buffer, data, len);
	if (rc < 0)
		goto out;

	rc = kstrtoint(buffer, 10, value);
out:
	kfree(buffer);
	return rc;
}

/**
 * ipe_get_audit_mode - retrieve the current value of the success_audit flag
 *			as a string representation.
 * @f: The file structure representing the securityfs entry. Unused.
 * @data: userspace buffer to place the result
 * @len: length of @data
 * @offset: offset into @data
 *
 * This is the handler for the 'read' syscall on the securityfs node,
 * ipe/success_audit
 *
 * Return:
 * > 0 - OK
 * < 0 - Error, see simple_read_from_buffer
 */
static ssize_t ipe_get_audit_mode(struct file *f, char __user *data, size_t len,
				  loff_t *offset)
{
	char tmp[3] = { 0 };

	snprintf(tmp, ARRAY_SIZE(tmp), "%c\n", (ipe_success_audit) ? '1' : '0');

	return simple_read_from_buffer(data, len, offset, tmp,
				       ARRAY_SIZE(tmp));
}

/**
 * ipe_set_audit_mode - change the value of the ipe_success_audit flag.
 * @f: The file structure representing the securityfs entry
 * @data: userspace buffer containing value to be set. Should be "1" or "0".
 * @len: length of @data
 * @offset: offset into @data
 *
 * Return:
 * > 0 - OK
 * -EPERM - if MAC system available, missing CAP_MAC_ADMIN.
 * -EINVAL - value written was not "1" or "0".
 */
static ssize_t ipe_set_audit_mode(struct file *f, const char __user *data, size_t len,
				  loff_t *offset)
{
	int v = 0;
	int rc = 0;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	rc = get_int_user(data, len, offset, &v);
	if (rc)
		return rc;

	if (v != 0 && v != 1)
		return -EINVAL;

	ipe_success_audit = v == 1;

	return len;
}

static const struct file_operations audit_ops = {
	.read = ipe_get_audit_mode,
	.write = ipe_set_audit_mode
};

#ifdef CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH

/**
 * ipe_get_enforce - retrieve the current value of the ipe_enforce flag
 *		     as a string representation.
 * @f: The file structure representing the securityfs entry. Unused.
 * @data: userspace buffer to place the result
 * @len: length of @data
 * @offset: offset into @data
 *
 * This is the handler for the 'read' syscall on the securityfs node,
 * ipe/enforce
 *
 * Return:
 * > 0 - OK
 * < 0 - Error, see simple_read_from_buffer
 */
static ssize_t ipe_get_enforce(struct file *f, char __user *data, size_t len,
			       loff_t *offset)
{
	char tmp[3] = { 0 };

	snprintf(tmp, ARRAY_SIZE(tmp), "%c\n", (ipe_enforce) ? '1' : '0');

	return simple_read_from_buffer(data, len, offset, tmp,
				       ARRAY_SIZE(tmp));
}

/**
 * ipe_set_enforce - change the value of the ipe_enforce flag.
 * @f: The file structure representing the securityfs entry
 * @data: userspace buffer containing value to be set. Should be "1" or "0".
 * @len: length of @data
 * @offset: offset into @data
 *
 * Return:
 * > 0 - OK
 * -EPERM - if MAC system available, missing CAP_MAC_ADMIN.
 * -EINVAL - value written was not "1" or "0".
 */
static ssize_t ipe_set_enforce(struct file *f, const char __user *data, size_t len,
			       loff_t *offset)
{
	int v = 0;
	int rc = 0;
	bool ret = 0;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	rc = get_int_user(data, len, offset, &v);
	if (rc)
		return rc;

	if (v != 0 && v != 1)
		return -EINVAL;

	ret = v == 1;

	if (ret != ipe_enforce)
		ipe_audit_mode(ret);

	ipe_enforce = ret;

	return len;
}

static const struct file_operations enforce_ops = {
	.read = ipe_get_enforce,
	.write = ipe_set_enforce
};

/**
 * ipe_init_enforce_node - Wrapper around securityfs_create_file for the
 *			   ipe/enforce securityfs node.
 * @root: securityfs node that is the parent of the new node to be created
 *
 * This allows this function to be no-op'd when the permissive switch is
 * disabled.
 *
 * Return:
 * See securityfs_create_file.
 */
static inline struct dentry *ipe_init_enforce_node(struct dentry *root)
{
	return securityfs_create_file(IPE_ENFORCE, 0644, root, NULL,
				      &enforce_ops);
}

#else

/**
 * ipe_init_enforce_node - Wrapper around securityfs_create_file for the
 *			   ipe/enforce securityfs node.
 * @root: Unused
 *
 * This allows this function to be no-op'd when the permissive switch is
 * disabled.
 *
 * Return:
 * NULL.
 */
static inline struct dentry *ipe_init_enforce_node(struct dentry *root)
{
	return NULL;
}

#endif /* CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH */

/**
 * retrieve_backed_dentry: Retrieve a dentry with a backing inode, identified
 *			   by @name, under @parent.
 * @name: Name of the dentry under @parent.
 * @parent: The parent dentry to search under for @name.
 * @size: Length of @name.
 *
 * This takes a reference to the returned dentry. Caller needs to call dput
 * to drop the reference.
 *
 * Return:
 * valid dentry - OK
 * ERR_PTR - Error, see lookup_one_len_unlocked
 * NULL - No backing inode was found
 */
static struct dentry *retrieve_backed_dentry(const char *name,
					     struct dentry *parent,
					     size_t size)
{
	struct dentry *tmp = NULL;

	tmp = lookup_one_len_unlocked(name, parent, size);
	if (IS_ERR(tmp))
		return tmp;

	if (!d_really_is_positive(tmp))
		return NULL;

	return tmp;
}

/**
 * alloc_size_cb: Callback for determining the allocation size of the grammar
 *		  buffer
 * @prop: ipe_property structure to determine allocation size
 * @ctx: void* representing a size_t* to add the allocation size to.
 *
 * Return:
 * 0 - Always
 */
static int alloc_size_cb(const struct ipe_property *prop, void *ctx)
{
	size_t *ref = ctx;
	char tmp[6] = { 0 };

	snprintf(tmp, ARRAY_SIZE(tmp), "%d", prop->version);

	/* property_name=u16\n */
	*ref += strlen(prop->property_name) + strlen(tmp) + 2;

	return 0;
}

/**
 * build_cfg_str: Callback to populate the previously-allocated string
 *		  buffer for ipe's grammar version with the content.
 * @prop: ipe_property structure to determine allocation size
 * @ctx: void* representing a char* to append the population to.
 *
 * Return:
 * 0 - Always
 */
static int build_cfg_str(const struct ipe_property *prop, void *ctx)
{
	char *ref = (char *)ctx;
	char tmp[6] = { 0 };

	snprintf(tmp, ARRAY_SIZE(tmp), "%d", prop->version);
	strcat(ref, prop->property_name);
	strcat(ref, "=");
	strcat(ref, tmp);
	strcat(ref, "\n");

	return 0;
}

/**
 * create_new_prop_cfg: create a new property configuration string for consumers
 *			of IPE policy.
 *
 * This function will iterate over all currently registered properties, and
 * return a string of form:
 *
 *	property1=version1\n
 *	property2=version2\n
 *	...
 *	propertyN=versionN
 *
 * Where propertyX is the property_name and versionX is the version associated.
 *
 * Return:
 * !ERR_PTR - Success
 * ERR_PTR(-ENOMEM) - Allocation Failed
 */
static char *create_new_prop_cfg(void)
{
	size_t i;
	ssize_t rc = 0;
	size_t alloc = 0;
	char *ret = NULL;
	const char *const built_ins[] = {
		IPE_PROPERTY_OPERATION_VER,
		IPE_PROPERTY_ACTION_VER,
		IPE_PROPERTY_DEFAULT_VER,
		IPE_HEADER_POLICY_NAME_VER,
		IPE_HEADER_POLICY_VERSION_VER
	};

	for (i = 0; i < ARRAY_SIZE(built_ins); ++i)
		alloc += strlen(built_ins[i]) + 1; /* \n */

	(void)ipe_for_each_prop(alloc_size_cb, (void *)&alloc);
	++alloc; /* null for strcat */

	ret = kzalloc(alloc, GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < ARRAY_SIZE(built_ins); ++i) {
		strcat(ret, built_ins[i]);
		strcat(ret,  "\n");
	}

	rc = ipe_for_each_prop(build_cfg_str, (void *)ret);
	if (rc)
		goto err;

	return ret;
err:
	kfree(ret);
	return ERR_PTR(rc);
}

/**
 * ipe_get_prop_cfg: Get (or allocate if one does not exist) the property
 *		     configuration string for IPE.
 *
 * @f: File representing the securityfs entry.
 * @data: User mode buffer to place the configuration string.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * As this string can only change on a new kernel build, this string
 * is cached in the i_private field of @f's inode for subsequent calls.
 *
 * Return:
 * < 0 - Error
 * > 0 - Success, bytes written to @data
 */
static ssize_t ipe_get_prop_cfg(struct file *f, char __user *data, size_t size,
				loff_t *offset)
{
	ssize_t rc = 0;
	const char *cfg = NULL;
	struct inode *grammar = d_inode(property_cfg_node);

	inode_lock(grammar);

	/*
	 * This can only change with a new kernel build,
	 * so cache the result in i->private
	 */
	if (IS_ERR_OR_NULL(grammar->i_private)) {
		grammar->i_private = create_new_prop_cfg();
		if (IS_ERR(grammar->i_private)) {
			rc = PTR_ERR(grammar->i_private);
			goto out;
		}
	}
	cfg = (const char *)grammar->i_private;

	rc = simple_read_from_buffer(data, size, offset, cfg, strlen(cfg));

out:
	inode_unlock(grammar);
	return rc;
}

static const struct file_operations prop_cfg_ops = {
	.read = ipe_get_prop_cfg
};

/**
 * ipe_free_policy_node: Free an ipe_policy_node structure allocated by
 *			 ipe_alloc_policy_node.
 * @n: ipe_policy_node to free
 */
static void ipe_free_policy_node(struct ipe_policy_node *n)
{
	if (IS_ERR_OR_NULL(n))
		return;

	ipe_free_policy(n->parsed);
	kfree(n->data);

	kfree(n);
}

/**
 * alloc_callback: Callback given to verify_pkcs7_signature function to set
 *		   the inner content reference and parse the policy.
 * @ctx: "ipe_policy_node" to set inner content, size and parsed policy of.
 * @data: Start of PKCS#7 inner content.
 * @len: Length of @data.
 * @asn1hdrlen: Unused.
 *
 * Return:
 * 0 - OK
 * ERR_PTR(-EBADMSG) - Invalid policy syntax
 * ERR_PTR(-ENOMEM) - Out of memory
 */
static int alloc_callback(void *ctx, const void *data, size_t len,
			  size_t asn1hdrlen)
{
	char *cpy = NULL;
	struct ipe_policy *pol = NULL;
	struct ipe_policy_node *n = (struct ipe_policy_node *)ctx;

	n->content = (const u8 *)data;
	n->content_size = len;

	if (len == 0)
		return -EBADMSG;

	cpy = kzalloc(len + 1, GFP_KERNEL);
	if (!cpy)
		return -ENOMEM;

	(void)memcpy(cpy, data, len);

	pol = ipe_parse_policy(cpy);
	if (IS_ERR(pol)) {
		kfree(cpy);
		return PTR_ERR(pol);
	}

	n->parsed = pol;
	kfree(cpy);
	return 0;
}

/**
 * ipe_delete_policy_tree - delete the policy subtree under
 *			    $securityfs/ipe/policies.
 * @policy_root: the policy root directory, i.e.
 *		 $securityfs/ipe/policies/$policy_name
 *
 * Return:
 * 0 - OK
 * -EPERM - Tree being deleted is the active policy
 * -ENOENT - A subnode is missing under the tree.
 * Other - see lookup_one_len_unlocked.
 */
static int ipe_delete_policy_tree(struct dentry *policy_root)
{
	int rc = 0;
	struct dentry *raw = NULL;
	struct dentry *active = NULL;
	struct dentry *content = NULL;
	struct dentry *delete = NULL;
	const struct ipe_policy_node *target = NULL;

	/* ensure the active policy cannot be changed */
	lockdep_assert_held(&ipe_policy_lock);

	/* fail if it's the active policy */
	target = (const struct ipe_policy_node *)d_inode(policy_root)->i_private;
	if (ipe_is_active_policy(target->parsed)) {
		rc = -EPERM;
		goto out;
	}

	raw = retrieve_backed_dentry(IPE_FULL_CONTENT, policy_root,
				     strlen(IPE_FULL_CONTENT));
	if (IS_ERR_OR_NULL(raw)) {
		rc = IS_ERR(raw) ? PTR_ERR(raw) : -ENOENT;
		goto out;
	}

	content = retrieve_backed_dentry(IPE_INNER_CONTENT, policy_root,
					 strlen(IPE_INNER_CONTENT));
	if (IS_ERR_OR_NULL(content)) {
		rc = IS_ERR(content) ? PTR_ERR(content) : -ENOENT;
		goto out_free_raw;
	}

	active = retrieve_backed_dentry(IPE_ACTIVE_POLICY, policy_root,
					strlen(IPE_ACTIVE_POLICY));
	if (IS_ERR_OR_NULL(active)) {
		rc = IS_ERR(active) ? PTR_ERR(active) : -ENOENT;
		goto out_free_content;
	}

	delete = retrieve_backed_dentry(IPE_DELETE_POLICY, policy_root,
					strlen(IPE_DELETE_POLICY));
	if (IS_ERR_OR_NULL(active)) {
		rc = IS_ERR(active) ? PTR_ERR(active) : -ENOENT;
		goto out_free_active;
	}

	inode_lock(d_inode(policy_root));
	ipe_free_policy_node(d_inode(policy_root)->i_private);
	d_inode(policy_root)->i_private = NULL;
	inode_unlock(d_inode(policy_root));

	/* drop references from acquired in this function */
	dput(raw);
	dput(content);
	dput(policy_root);
	dput(active);
	dput(delete);

	/* drop securityfs' references */
	securityfs_remove(raw);
	securityfs_remove(content);
	securityfs_remove(policy_root);
	securityfs_remove(active);
	securityfs_remove(delete);

	return rc;

out_free_active:
	dput(active);
out_free_content:
	dput(content);
out_free_raw:
	dput(raw);
out:
	return rc;
}

/**
 * ipe_delete_policy: Delete a policy, which is stored in this file's parent
 *		      dentry's inode.
 * @f: File representing the securityfs entry.
 * @data: Buffer containing the value 1.
 * @len: sizeof(u8).
 * @offset: Offset into @data.
 *
 * Return:
 * > 0 - OK
 * -ENOMEM - Out of memory
 * -EINVAL - Incorrect parameter
 * -EPERM - Policy is active
 * -ENOENT - A policy subnode does not exist
 * -EPERM - if a MAC subsystem is enabled, missing CAP_MAC_ADMIN
 * Other - See retrieve_backed_dentry
 */
static ssize_t ipe_delete_policy(struct file *f, const char __user *data,
				 size_t len, loff_t *offset)
{
	int v = 0;
	ssize_t rc = 0;
	struct inode *policy_i = NULL;
	struct dentry *policy_root = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	rc = get_int_user(data, len, offset, &v);
	if (rc)
		return rc;

	if (v != 1)
		return -EINVAL;

	policy_root = f->f_path.dentry->d_parent;
	policy_i = d_inode(policy_root);

	if (!policy_i->i_private)
		return -ENOENT;

	/* guarantee active policy cannot change */
	mutex_lock(&ipe_policy_lock);

	rc = ipe_delete_policy_tree(policy_root);
	if (rc)
		goto out_unlock;

	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();

	return len;

out_unlock:
	mutex_unlock(&ipe_policy_lock);
	return rc;
}

static const struct file_operations policy_delete_ops = {
	.write = ipe_delete_policy
};

/**
 * ipe_alloc_policy_node: Allocate a new ipe_policy_node structure.
 * @data: Raw enveloped PKCS#7 data that represents the policy.
 * @len: Length of @data.
 *
 * Return:
 * valid ipe_policy_node - OK
 * ERR_PTR(-EBADMSG) - Invalid policy syntax
 * ERR_PTR(-ENOMEM) - Out of memory
 */
static struct ipe_policy_node *ipe_alloc_policy_node(const u8 *data,
						     size_t len)
{
	int rc = 0;
	struct ipe_policy_node *node = NULL;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		rc = -ENOMEM;
		goto out;
	}

	node->data_len = len;
	node->data = kmemdup(data, len, GFP_KERNEL);
	if (!node->data) {
		rc = -ENOMEM;
		goto out2;
	}

	rc = verify_pkcs7_signature(node->content, node->content_size,
				    node->data, node->data_len, NULL,
				    VERIFYING_UNSPECIFIED_SIGNATURE,
				    alloc_callback, node);
	if (rc != 0)
		goto out2;

	return node;
out2:
	ipe_free_policy_node(node);
out:
	return ERR_PTR(rc);
}

/**
 * ipe_read_policy: Read the raw content (full enveloped PKCS7) data of
 *			the policy stored within the file's parent inode.
 * @f: File representing the securityfs entry.
 * @data: User mode buffer to place the raw pkcs7.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * Return:
 * > 0 - OK
 * -ENOMEM - Out of memory
 */
static ssize_t ipe_read_policy(struct file *f, char __user *data,
			       size_t size, loff_t *offset)
{
	ssize_t rc = 0;
	size_t avail = 0;
	struct inode *root = NULL;
	const struct ipe_policy_node *node = NULL;

	root = d_inode(f->f_path.dentry->d_parent);

	inode_lock_shared(root);
	node = (const struct ipe_policy_node *)root->i_private;

	avail = node->data_len;
	rc = simple_read_from_buffer(data, size, offset, node->data, avail);

	inode_unlock_shared(root);
	return rc;
}

/**
 * ipe_update_policy: Update a policy in place with a new PKCS7 policy.
 * @f: File representing the securityfs entry.
 * @data: Buffer user mode to place the raw pkcs7.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Invalid policy format
 * -ENOMEM - Out of memory
 * -EPERM - if a MAC subsystem is enabled, missing CAP_MAC_ADMIN
 * -EINVAL - Incorrect policy name for this node, or version is < current
 */
static ssize_t ipe_update_policy(struct file *f, const char __user *data,
				 size_t len, loff_t *offset)
{
	ssize_t rc = 0;
	u8 *cpy = NULL;
	struct inode *root = NULL;
	struct crypto_shash *tfm = NULL;
	struct ipe_policy_node *new = NULL;
	struct ipe_policy_node *old = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	cpy = memdup_user(data, len);
	if (IS_ERR(cpy))
		return PTR_ERR(cpy);

	new = ipe_alloc_policy_node(cpy, len);
	if (IS_ERR(new)) {
		rc = PTR_ERR(new);
		goto out_free_cpy;
	}

	tfm = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(tfm))
		goto out_free_node;

	root = d_inode(f->f_path.dentry->d_parent);
	inode_lock(root);
	mutex_lock(&ipe_policy_lock);

	old = (struct ipe_policy_node *)root->i_private;

	if (strcmp(old->parsed->policy_name, new->parsed->policy_name)) {
		rc = -EINVAL;
		goto out_unlock_inode;
	}

	if (!ipe_is_valid_policy(old->parsed, new->parsed)) {
		rc = -EINVAL;
		goto out_unlock_inode;
	}

	rc = ipe_update_active_policy(old->parsed, new->parsed);
	if (rc != 0)
		goto out_unlock_inode;

	ipe_audit_policy_load(new->parsed, new->data, new->data_len, tfm);
	swap(root->i_private, new);

	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();

	inode_unlock(root);
	kfree(cpy);
	ipe_free_policy_node(new);
	crypto_free_shash(tfm);

	return len;

out_unlock_inode:
	mutex_unlock(&ipe_policy_lock);
	inode_unlock(root);
	crypto_free_shash(tfm);
out_free_node:
	ipe_free_policy_node(new);
out_free_cpy:
	kfree(cpy);
	return rc;
}

static const struct file_operations policy_raw_ops = {
	.read = ipe_read_policy,
	.write = ipe_update_policy
};

/**
 * ipe_read_content: Read the inner content of the enveloped PKCS7 data,
 *			 representing the IPE policy.
 * @f: File representing the securityfs entry.
 * @data: User mode buffer to place the inner content of the pkcs7 data.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * Return:
 * > 0 - OK
 * -ENOMEM - Out of memory
 */
static ssize_t ipe_read_content(struct file *f, char __user *data,
				size_t size, loff_t *offset)
{
	ssize_t rc = 0;
	size_t avail = 0;
	struct inode *root = NULL;
	const struct ipe_policy_node *node = NULL;

	root = d_inode(f->f_path.dentry->d_parent);

	inode_lock_shared(root);
	node = (const struct ipe_policy_node *)root->i_private;

	avail = node->content_size;
	rc = simple_read_from_buffer(data, size, offset, node->content, avail);

	inode_unlock_shared(root);
	return rc;
}

static const struct file_operations policy_content_ops = {
	.read = ipe_read_content
};

/**
 * ipe_get_active - return a string representation of whether a policy
 *		    is active.
 * @f: File struct representing the securityfs node. Unused.
 * @data: buffer to place the result.
 * @len: length of @data.
 * @offset: offset into @data.
 *
 * This is the 'read' syscall handler for
 * $securityfs/ipe/policies/$policy_name/active
 *
 * Return:
 * > 0 - OK
 * < 0 - see simple_read_from_buffer.
 */
static ssize_t ipe_get_active(struct file *f, char __user *data, size_t len,
			      loff_t *offset)
{
	ssize_t rc = 0;
	char tmp[3] = { 0 };
	struct inode *root = NULL;
	const struct ipe_policy_node *node = NULL;

	root = d_inode(f->f_path.dentry->d_parent);
	inode_lock_shared(root);

	node = (const struct ipe_policy_node *)root->i_private;

	snprintf(tmp, ARRAY_SIZE(tmp), "%c\n",
		 ipe_is_active_policy(node->parsed) ? '1' : '0');

	rc = simple_read_from_buffer(data, len, offset, tmp,
				     ARRAY_SIZE(tmp));

	inode_unlock_shared(root);

	return rc;
}

/**
 * ipe_set_active - mark a policy as active, causing IPE to start enforcing
 *		    this policy.
 * @f: File struct representing the securityfs node.
 * @data: buffer containing data written to the securityfs node..
 * @len: length of @data.
 * @offset: offset into @data.
 *
 * This is the 'write' syscall handler for
 * $securityfs/ipe/policies/$policy_name/active
 *
 * Return:
 * > 0 - OK
 * -EINVAL - Value written is not "1".
 * -EPERM - if MAC system is enabled, missing CAP_MAC_ADMIN.
 * Other - see ipe_activate_policy, get_int_user
 */
static ssize_t ipe_set_active(struct file *f, const char __user *data, size_t len,
			      loff_t *offset)
{
	int v = 0;
	ssize_t rc = 0;
	struct inode *root = NULL;
	const struct ipe_policy_node *node = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	rc = get_int_user(data, len, offset, &v);
	if (rc)
		return rc;

	if (v != 1)
		return -EINVAL;

	root = d_inode(f->f_path.dentry->d_parent);
	mutex_lock(&ipe_policy_lock);
	inode_lock_shared(root);

	node = (const struct ipe_policy_node *)root->i_private;
	rc = ipe_activate_policy(node->parsed);

	inode_unlock_shared(root);
	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();

	return (!rc) ? len : rc;
}

static const struct file_operations policy_active_ops = {
	.read = ipe_get_active,
	.write = ipe_set_active
};

/**
 * ipe_alloc_policy_tree - allocate the proper subnodes for a policy under
 *			   securityfs.
 * @parent: The parent directory that these securityfs files should be created
 *	    under.
 *
 * Return:
 * 0 - OK
 * !0 - See securityfs_create_file
 */
static int ipe_alloc_policy_tree(struct dentry *parent)
{
	int rc = 0;
	struct dentry *raw = NULL;
	struct dentry *delete = NULL;
	struct dentry *active = NULL;
	struct dentry *content = NULL;

	raw = securityfs_create_file(IPE_FULL_CONTENT, 0644, parent, NULL,
				     &policy_raw_ops);
	if (IS_ERR(raw))
		return PTR_ERR(raw);

	content = securityfs_create_file(IPE_INNER_CONTENT, 0444, parent,
					 NULL, &policy_content_ops);
	if (IS_ERR(raw)) {
		rc = PTR_ERR(raw);
		goto free_raw;
	}

	active = securityfs_create_file(IPE_ACTIVE_POLICY, 0644, parent, NULL,
					&policy_active_ops);
	if (IS_ERR(active)) {
		rc = PTR_ERR(active);
		goto free_content;
	}

	delete = securityfs_create_file(IPE_DELETE_POLICY, 0644, parent, NULL,
					&policy_delete_ops);
	if (IS_ERR(delete)) {
		rc = PTR_ERR(delete);
		goto free_active;
	}

	return rc;

free_active:
	securityfs_remove(active);
free_content:
	securityfs_remove(content);
free_raw:
	securityfs_remove(raw);

	return rc;
}

/**
 * ipe_build_policy_node: Build a new securityfs node for IPE policies.
 * @data: Raw enveloped PKCS#7 data that represents the policy.
 * @len: Length of @data.
 *
 * Return:
 * 0 - OK
 * -EEXIST - Policy already exists
 * -EBADMSG - Invalid policy syntax
 * -ENOMEM - Out of memory
 */
static int ipe_build_policy_node(const u8 *data, size_t len)
{
	int rc = 0;
	struct dentry *root = NULL;
	struct inode *root_i = NULL;
	struct crypto_shash *tfm = NULL;
	struct ipe_policy_node *node = NULL;

	tfm = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(tfm)) {
		rc = PTR_ERR(tfm);
		goto out;
	}

	node = ipe_alloc_policy_node(data, len);
	if (IS_ERR(node)) {
		rc = PTR_ERR(node);
		goto free_hash;
	}

	root = securityfs_create_dir(node->parsed->policy_name,
				     policies_root);
	if (IS_ERR(root)) {
		rc = PTR_ERR(root);
		goto free_private;
	}

	root_i = d_inode(root);

	inode_lock(root_i);
	root_i->i_private = node;
	ipe_audit_policy_load(node->parsed, node->data, node->data_len, tfm);
	inode_unlock(root_i);

	rc = ipe_alloc_policy_tree(root);
	if (rc)
		goto free_secfs;

	crypto_free_shash(tfm);
	return rc;

free_secfs:
	securityfs_remove(root);
free_private:
	ipe_free_policy_node(node);
free_hash:
	crypto_free_shash(tfm);
out:
	return rc;
}

/**
 * ipe_new_policy: Entry point of the securityfs node, "ipe/new_policy".
 * @f: File representing the securityfs entry.
 * @data: Raw enveloped PKCS#7 data that represents the policy.
 * @len: Length of @data.
 * @offset: Offset for @data.
 *
 * Return:
 * > 0 - OK
 * -EEXIST - Policy already exists
 * -EBADMSG - Invalid policy syntax
 * -ENOMEM - Out of memory
 * -EPERM - if a MAC subsystem is enabled, missing CAP_MAC_ADMIN
 */
static ssize_t ipe_new_policy(struct file *f, const char __user *data,
			      size_t len, loff_t *offset)
{
	ssize_t rc = 0;
	u8 *cpy = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	cpy = memdup_user(data, len);
	if (IS_ERR(cpy))
		return PTR_ERR(cpy);

	rc = ipe_build_policy_node(cpy, len);

	kfree(cpy);
	return rc < 0 ? rc : len;
}

static const struct file_operations new_policy_ops = {
	.write = ipe_new_policy
};

/**
 * ipe_build_secfs_root: Build the root of securityfs for IPE.
 *
 * Return:
 * 0 - OK
 * !0 - See securityfs_create_dir and securityfs_create_file
 */
static int __init ipe_build_secfs_root(void)
{
	int rc = 0;
	struct dentry *new = NULL;
	struct dentry *cfg = NULL;
	struct dentry *root = NULL;
	struct dentry *audit = NULL;
	struct dentry *enforce = NULL;
	struct dentry *policies = NULL;

	root = securityfs_create_dir(IPE_ROOT, NULL);
	if (IS_ERR(root)) {
		rc = PTR_ERR(root);
		goto out;
	}

	new = securityfs_create_file(NEW_POLICY, 0644, root, NULL,
				     &new_policy_ops);
	if (IS_ERR(new)) {
		rc = PTR_ERR(new);
		goto out_free_root;
	}

	policies = securityfs_create_dir(IPE_POLICIES, root);
	if (IS_ERR(policies)) {
		rc = PTR_ERR(policies);
		goto out_free_new;
	}

	cfg = securityfs_create_file(IPE_PROPERTY_CFG, 0444, root, NULL,
				     &prop_cfg_ops);
	if (IS_ERR(cfg)) {
		rc = PTR_ERR(cfg);
		goto out_free_policies;
	}

	audit = securityfs_create_file(IPE_SUCCESS_AUDIT, 0644, root, NULL,
				       &audit_ops);
	if (IS_ERR(cfg)) {
		rc = PTR_ERR(audit);
		goto out_free_cfg;
	}

	enforce = ipe_init_enforce_node(root);
	if (IS_ERR(enforce)) {
		rc = PTR_ERR(audit);
		goto out_free_audit;
	}

	securityfs_root = root;
	new_policy_node = new;
	policies_root = policies;
	property_cfg_node = cfg;
	success_audit_node = audit;
	enforce_node = enforce;

	return rc;

out_free_audit:
	securityfs_remove(audit);
out_free_cfg:
	securityfs_remove(cfg);
out_free_policies:
	securityfs_remove(policies);
out_free_new:
	securityfs_remove(new);
out_free_root:
	securityfs_remove(root);
out:
	return rc;
}

/**
 * ipe_build_boot_node: Build a policy node for IPE's boot policy.
 *
 * This differs from the normal policy nodes, as the IPE boot policy is
 * read only, and only has the 'content' and 'active' nodes (as it is
 * unsigned).
 *
 * Return:
 * 0 - OK
 * !0 - See securityfs_create_dir and securityfs_create_file
 */
static int __init ipe_build_boot_node(void)
{
	int rc = 0;
	char *cpy = NULL;
	struct inode *root_i = NULL;
	struct dentry *root = NULL;
	struct dentry *active = NULL;
	struct dentry *content = NULL;
	struct ipe_policy *parsed = NULL;
	struct ipe_policy_node *node = NULL;

	if (!ipe_boot_policy)
		return 0;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		rc = -ENOMEM;
		goto out;
	}

	cpy = kstrdup(ipe_boot_policy, GFP_KERNEL);
	if (!cpy) {
		rc = -ENOMEM;
		goto out;
	}

	parsed = ipe_parse_policy(cpy);
	if (IS_ERR(parsed)) {
		rc = PTR_ERR(parsed);
		goto out_free_policy;
	}

	node->content = ipe_boot_policy;
	node->content_size = strlen(ipe_boot_policy);
	node->parsed = parsed;

	root = securityfs_create_dir(node->parsed->policy_name,
				     policies_root);
	if (IS_ERR(root)) {
		rc = PTR_ERR(root);
		goto out_free_policy;
	}

	content = securityfs_create_file(IPE_INNER_CONTENT, 0444, root, NULL,
					 &policy_content_ops);
	if (IS_ERR(content)) {
		rc = PTR_ERR(content);
		goto out_free_root;
	}

	active = securityfs_create_file(IPE_ACTIVE_POLICY, 0644, root, NULL,
					&policy_active_ops);
	if (IS_ERR(active)) {
		rc = PTR_ERR(active);
		goto out_free_content;
	}

	root_i = d_inode(root);

	inode_lock(root_i);
	root_i->i_private = node;
	inode_unlock(root_i);

	boot_policy_node = root;
	mutex_lock(&ipe_policy_lock);
	rc = ipe_activate_policy(node->parsed);
	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();

	return rc;

out_free_content:
	securityfs_remove(content);
out_free_root:
	securityfs_remove(root);
out_free_policy:
	ipe_free_policy(parsed);
out:
	kfree(cpy);
	kfree(node);
	return rc;
}

/**
 * ipe_securityfs_init: Initialize IPE's securityfs entries.
 *
 * This is called after the lsm initialization.
 *
 * Return:
 * 0 - OK
 * !0 - Error
 */
static int __init ipe_securityfs_init(void)
{
	int rc = 0;

	rc = ipe_build_secfs_root();
	if (rc != 0)
		goto err;

	rc = ipe_build_boot_node();
	if (rc != 0)
		panic("IPE failed to initialize the boot policy: %d", rc);

	return rc;
err:
	pr_err("failed to initialize secfs: %d", -rc);
	return rc;
}

core_initcall(ipe_securityfs_init);
