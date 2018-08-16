#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "vmmapi.h"
#include "tpm.h"

#define STR_MAX_LEN 1024U
static char *path;

static bool need_vtpm2 = false;

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
			fprintf(stderr, "Invalid vtpm path\n");
			return -1;
		}
		path = calloc(len + 1, 1);
		if (!path)
			return -1;
		strcpy(path, value);
	}
	need_vtpm2 = true;

	return 0;
}

void init_vtpm2(struct vmctx *ctx)
{
	if (need_vtpm2) {

		init_tpm_emulator(path);

		init_tpm_crb(ctx);
	}
}

void deinit_vtpm2(struct vmctx *ctx)
{
	if (ctx->tpm_dev) {
		deinit_tpm_crb(ctx);
		if (path)
			free(path);
	}
}
