/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "vmmapi.h"
#include "tpm.h"
#include "tpm_internal.h"

static int tpm_debug;
#define LOG_TAG "tpm: "
#define DPRINTF(fmt, args...) \
	do { if (tpm_debug) printf(LOG_TAG "%s:" fmt, __func__, ##args); } while (0)
#define WPRINTF(fmt, args...) \
	do { printf(LOG_TAG "%s:" fmt, __func__, ##args); } while (0)

#define STR_MAX_LEN 1024U
static char *sock_path = NULL;

enum {
	SOCK_PATH_OPT = 0
};

char *const token[] = {
	[SOCK_PATH_OPT] = "sock_path",
	NULL
};

int acrn_parse_vtpm2(char *arg)
{
	char *value;
	size_t len = strlen(arg);

	if (len > STR_MAX_LEN)
		return -1;

	if (SOCK_PATH_OPT == getsubopt(&arg, token, &value)) {
		if (value == NULL) {
			DPRINTF("Invalid vtpm socket path\n");
			return -1;
		}
		sock_path = calloc(len + 1, 1);
		if (!sock_path)
			return -1;
		strcpy(sock_path, value);
	}

	return 0;
}

void init_vtpm2(struct vmctx *ctx)
{
	if (!sock_path) {
		WPRINTF("Invalid socket path!\n");
		return;
	}

	if (init_tpm_emulator(sock_path) < 0) {
		WPRINTF("Failed init tpm emulator!\n");
		return;
	}

	if (init_tpm_crb(ctx) < 0) {
		WPRINTF("Failed init tpm emulator!\n");
	}
}

void deinit_vtpm2(struct vmctx *ctx)
{
	if (ctx->tpm_dev) {
		deinit_tpm_crb(ctx);

		deinit_tpm_emulator();

		if (sock_path)
			free(sock_path);
	}
}
