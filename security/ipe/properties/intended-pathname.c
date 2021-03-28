// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "../ipe.h"
#include "../ipe-pin.h"
#include "../ipe-property.h"
#include "../utility.h"

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/audit.h>
#include <linux/string.h>

#define WILDCARD_STR "*"
#define WILDCARD WILDCARD_STR[0]
#define PROPERTY_NAME "intended_pathname"

static void audit(struct audit_buffer *ab, const char *value)
{
	audit_log_format(ab, "'%s'", value);
}

static inline void audit_rule_value(struct audit_buffer *ab,
				    const void *value)
{
	audit(ab, (const char *)value);
}

static inline void audit_ctx(struct audit_buffer *ab,
			     const struct ipe_engine_ctx *ctx)
{
	if (ctx->sec_file && ctx->sec_file->app_path)
		audit_log_untrustedstring(ab, ctx->sec_file->app_path);
	else
		audit_log_format(ab, "NULL");
}

static bool evaluate(const struct ipe_engine_ctx *ctx,
		     const void *value)
{
	size_t len;
	const char *rule_pattern = (const char *)value;
	const char *app_path;
	const char *match;

	if (!ctx->sec_file || !ctx->sec_file->app_path)
		return false;

	app_path = ctx->sec_file->app_path;
	match = strstr(rule_pattern, WILDCARD_STR);

	/* no wildcard */
	if (!match) {
		match = rule_pattern;
		len = strlen(match);
	} else {
		len = match - rule_pattern;
	}

	return !strncmp(rule_pattern, app_path, len);
}

static int parse(const char *val_str, void **value)
{
	char *last_wildcard, *first_wildcard;

	/* ensure a wildcard is postfix, if one is present */
	last_wildcard = strrchr(val_str, WILDCARD);
	if (last_wildcard) {
		first_wildcard = strchr(val_str, WILDCARD);

		if (last_wildcard != first_wildcard)
			return -EINVAL;

		++last_wildcard;
		if (*last_wildcard != '\0')
			return -EINVAL;
	}

	*value = kstrdup(val_str, GFP_KERNEL);
	if (!(*value))
		return -ENOMEM;

	return 0;
}

static int duplicate(const void *src, void **dest)
{
	*dest = kstrdup(src, GFP_KERNEL);
	if (!(*dest))
		return -ENOMEM;

	return 0;
}

static void free_val(void **value)
{
	kfree(*value);
}

static const struct ipe_property intended_pathname = {
	.property_name = PROPERTY_NAME,
	.eval = evaluate,
	.parse = parse,
	.rule_audit = audit_rule_value,
	.ctx_audit = audit_ctx,
	.dup = duplicate,
	.free_val = free_val,
};

int ipe_init_intended_pathname(void)
{
	return ipe_register_property(&intended_pathname);
}
