/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SEED_PARSE_H_
#define SEED_PARSE_H_

#define SEED_ENTRY_TYPE_SVNSEED         0x1U
#define SEED_ENTRY_TYPE_RPMBSEED        0x2U

#define SEED_ENTRY_USAGE_USEED          0x1U
#define SEED_ENTRY_USAGE_DSEED          0x2U

struct seed_list_hob {
	uint8_t revision;
	uint8_t reserved0[3];
	uint32_t buffer_size;
	uint8_t total_seed_count;
	uint8_t reserved1[3];
};

struct seed_entry {
	/* SVN based seed or RPMB seed or attestation key_box */
	uint8_t type;
	/* For SVN seed: useed or dseed
	 * For RPMB seed: serial number based or not
	 */
	uint8_t usage;
	/* index for the same type and usage seed */
	uint8_t index;
	uint8_t reserved;
	/* reserved for future use */
	uint16_t flags;
	/* Total size of this seed entry */
	uint16_t seed_entry_size;
	/* SVN seed: struct seed_info
	 * RPMB seed: uint8_t rpmb_key[key_len]
	 */
	uint8_t seed[0];
};

void parse_seed_list_sbl(struct seed_list_hob *seed_hob);


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

void parse_seed_list_abl(void *boot_params, uint8_t *serial, uint32_t serial_len);

#endif /* SEED_PARSE_H_ */
