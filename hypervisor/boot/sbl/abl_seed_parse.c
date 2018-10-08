/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <hypervisor.h>
#include <abl_seed_parse.h>
#include <hkdf_wrap.h>

#define MMC_SERIAL_LEN 15U

#define ABL_SEED_LEN 32U
struct abl_seed_info {
	uint8_t svn;
	uint8_t reserved[3];
	uint8_t seed[ABL_SEED_LEN];
};

#define ABL_SEED_LIST_MAX 4U
struct dev_sec_info {
	uint32_t size_of_this_struct;
	uint32_t version;
	uint32_t num_seeds;
	struct abl_seed_info seed_list[ABL_SEED_LIST_MAX];
};

static const char *boot_params_arg = "dev_sec_info.param_addr=";

static void get_emmc_serial(char *cmdline, uint8_t *serial)
{
	char *arg;
	char *param;
	uint32_t len;

	len = strnlen_s("androidboot.serialno=", MEM_2K);
	arg = strstr_s(cmdline, MEM_2K, "androidboot.serialno=", len);

	if (arg == NULL) {
		memcpy_s(serial, MMC_SERIAL_LEN, "123456789abcde", MMC_SERIAL_LEN);
		return;
	}

	param = arg + len;

	memcpy_s(serial, MMC_SERIAL_LEN, param, MMC_SERIAL_LEN-1);
	serial[MMC_SERIAL_LEN-1] = '\0';
}

static void parse_seed_list_abl(void *param_addr, uint8_t *serial)
{
	uint32_t i;
	struct seed_info dseed_list[BOOTLOADER_SEED_MAX_ENTRIES];
	struct dev_sec_info *sec_info = (struct dev_sec_info *)param_addr;

	if (sec_info == NULL)
		goto fail;

	(void)memset(dseed_list, 0U, sizeof(dseed_list));
	for (i = 0U; i < sec_info->num_seeds; i++) {
		dseed_list[i].cse_svn = sec_info->seed_list[i].svn;
		(void)memcpy_s(dseed_list[i].seed,
				sizeof(dseed_list[i].seed),
				sec_info->seed_list[i].seed,
				sizeof(sec_info->seed_list[i].seed));

		/* replace original seeds with new seeds(derived with emmc serial) */
		if (hkdf_sha256(sec_info->seed_list[i].seed,
				sizeof(sec_info->seed_list[i].seed),
				dseed_list[i].seed,
				sizeof(dseed_list[i].seed),
				NULL, 0U,
				serial, MMC_SERIAL_LEN-1) == 0U) {
			/* Failed derive key, use fake seed */
			(void)memset(sec_info->seed_list[i].seed, 0xFA,
					sizeof(sec_info->seed_list[i].seed));
		}
	}


	trusty_set_dseed(dseed_list, sec_info->num_seeds);
	(void)memset(dseed_list, 0U, sizeof(dseed_list));
	return;
fail:
	trusty_set_dseed(NULL, 0U);
	(void)memset(dseed_list, 0U, sizeof(dseed_list));
}

bool abl_seed_parse(struct vm *vm, char *cmdline, char *out_arg, uint32_t out_len)
{
	char *arg, *arg_end;
	char *param;
	void *param_addr;
	uint32_t len;
	uint8_t serial[MMC_SERIAL_LEN];

	if (cmdline == NULL) {
		goto fail;
	}

	len = strnlen_s(boot_params_arg, MEM_1K);
	arg = strstr_s(cmdline, MEM_2K, boot_params_arg, len);

	if (arg == NULL) {
		goto fail;
	}

	param = arg + len;
	param_addr = (void *)hpa2hva(strtoul_hex(param));
	if (param_addr == NULL) {
		goto fail;
	}

	get_emmc_serial(cmdline, serial);
	parse_seed_list_abl(param_addr, serial);

	/*
	 * Replace original arguments with spaces since SOS's GPA is not
	 * identity mapped to HPA. The argument will be appended later when
	 * compose cmdline for SOS.
	 */
	arg_end = strchr(arg, ' ');
	len = (arg_end != NULL) ? (uint32_t)(arg_end - arg) :
							strnlen_s(arg, MEM_2K);
	(void)memset(arg, ' ', len);

	if (out_arg) {
		snprintf(out_arg, out_len, "%s0x%X ",
			boot_params_arg, hva2gpa(vm, param_addr));
	}

	return true;

fail:
	parse_seed_list_abl(NULL, NULL);
	return false;
}
