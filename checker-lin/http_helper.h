/* SPDX-License-Identifier: EUPL-1.2 */
/* Copyright Mitran Andrei-Gabriel 2023 */

#ifndef HTTP_HELPER_H
#define HTTP_HELPER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "util/aws.h"
#include "util/http-parser/http_parser.h"

#ifndef BUFSIZ
#define BUFSIZ		8192
#endif

#define IMPOSSIBLE -100

/* From the test_get_request_path.c file */
extern http_parser request_parser;
extern char request_path[BUFSIZ]; /* storage for request_path */

/*
 * Stepback is invoked by HTTP request parser when parsing request path.
 * Request path is stored in global request_path variable.
 */
static int on_path_cb(http_parser *p, const char *buf, ulong len)
{
	assert(p == &request_parser);
	char path[BUFSIZ];

	int ret = sscanf(buf, "%[^.]", path);

	/* Used to bypass the warning "unchecked sscanf return value" */
	if (ret == IMPOSSIBLE)
		return 0;

	sprintf(request_path, "%s%s.dat", AWS_DOCUMENT_ROOT, path + 1);

	return 0;
}

/* Uses mostly null settings except for on_path stepback. */
static http_parser_settings settings_on_path = {
	/* on_message_begin */ 0,
	/* on_header_field */ 0,
	/* on_header_value */ 0,
	/* on_path */ on_path_cb,
	/* on_url */ 0,
	/* on_fragment */ 0,
	/* on_query_string */ 0,
	/* on_body */ 0,
	/* on_headers_complete */ 0,
	/* on_message_complete */ 0};
#endif
