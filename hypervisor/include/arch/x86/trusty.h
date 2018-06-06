/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TRUSTY_H_
#define TRUSTY_H_

#define BOOTLOADER_SEED_MAX_ENTRIES    10
#define RPMB_MAX_PARTITION_NUMBER       6
#define MMC_PROD_NAME_WITH_PSN_LEN      15
#define BUP_MKHI_BOOTLOADER_SEED_LEN    64

#define SEED_ENTRY_TYPE_SVNSEED         0x1
#define SEED_ENTRY_TYPE_RPMBSEED        0x2

#define SEED_ENTRY_USAGE_USEED          0x1
#define SEED_ENTRY_USAGE_DSEED          0x2

/* Trusty EPT rebase gpa: 511G */
#define TRUSTY_EPT_REBASE_GPA (511ULL*1024ULL*1024ULL*1024ULL)
#define TRUSTY_MEMORY_SIZE        0x01000000

/* Structure of seed info */
struct seed_info {
	uint8_t cse_svn;
	uint8_t bios_svn;
	uint8_t padding[2];
	uint8_t seed[BUP_MKHI_BOOTLOADER_SEED_LEN];
};

/* Structure of key info */
struct key_info {
	uint32_t size_of_this_struct;

	/* version info:
		0: baseline structure
		1: add ** new field
	 */
	uint32_t version;

	/* platform:
		0: Dummy (fake secret)
		1: APL (APL + ABL)
		2: ICL (ICL + SBL)
		3: CWP (APL|ICL + SBL + CWP)
		4: Brillo (Android Things)
	*/
	uint32_t platform;

	/* flags info:
		Bit 0: manufacturing state (0:manufacturing done;
					    1:in manufacturing mode)
		Bit 1: secure boot state (0:disabled; 1: enabled)
		Bit 2: test seeds (ICL only - 0:production seeds; 1: test seeds)
		other bits all reserved as 0
	*/
	uint32_t flags;

	/* Keep 64-bit align */
	uint32_t pad1;

	/* Seed list, include useeds(user seeds) and dseed(device seeds) */
	uint32_t num_seeds;
	struct seed_info useed_list[BOOTLOADER_SEED_MAX_ENTRIES];
	struct seed_info dseed_list[BOOTLOADER_SEED_MAX_ENTRIES];

	/* For ICL+ */
	/* rpmb keys, Currently HMAC-SHA256 is used in RPMB spec
	 * and 256-bit (32byte) is enough. Hence only lower 32 bytes will be
	 * used for now for each entry. But keep higher 32 bytes for future
	 * extension. Note that, RPMB keys are already tied to storage device
	 * serial number.If there are multiple RPMB partitions, then we will
	 * get multiple available RPMB keys. And if rpmb_key[n][64] == 0,
	 * then the n-th RPMB key is unavailable (Either because of no such
	 *  RPMB partition, or because OSloader doesn't want to share
	 *  the n-th RPMB key with Trusty)
	 */
	uint8_t rpmb_key[RPMB_MAX_PARTITION_NUMBER][64];

	/* 256-bit AES encryption key to encrypt/decrypt attestation keybox,
	   this key should be derived from a fixed key which is RPMB seed.
	   RPMB key (HMAC key) and this encryption key (AES key) are both
	   derived from the same RPMB seed.
	*/
	uint8_t attkb_enc_key[32];

	/* For APL only */
	/* RPMB key is derived with dseed together with this serial number,
	 * for ICL +, CSE directly provides the rpmb_key which is already
	 * tied to serial number. Concatenation of emmc product name
	 * with a string representation of PSN
	 */
	char serial[MMC_PROD_NAME_WITH_PSN_LEN];
	char pad2;
};

struct secure_world_memory {
	/* The secure world base address of GPA in SOS */
	uint64_t base_gpa;
	/* The secure world base address of HPA */
	uint64_t base_hpa;
	/* Secure world runtime memory size */
	uint64_t length;
};

struct secure_world_control {
	/* Whether secure world is enabled for current VM */
	bool sworld_enabled;
	/* Secure world memory structure */
	struct secure_world_memory sworld_memory;
};

struct trusty_startup_param {
	uint32_t size_of_this_struct;
	uint32_t mem_size;
	uint64_t tsc_per_ms;
	uint64_t trusty_mem_base;
	uint32_t reserved;
	uint8_t padding[4];
};

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

void switch_world(struct vcpu *vcpu, int next_world);
bool initialize_trusty(struct vcpu *vcpu, uint64_t param);
void destroy_secure_world(struct vm *vm);
void init_seed_list(struct seed_list_hob *seed_hob);

#endif /* TRUSTY_H_ */

