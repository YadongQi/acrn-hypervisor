/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <hypervisor.h>
#include <hypercall.h>

#define ACRN_DBG_TEE_HYCALL 6U

/* this hcall is only come from tee enabled vcpu itself, and cannot be
 * called from other vcpus
 */
int32_t hcall_initialize_tee(struct acrn_vcpu *vcpu, uint64_t param)
{
	if (vcpu->vm->sworld_control.flag.supported == 0UL) {
		dev_dbg(ACRN_DBG_TEE_HYCALL,
			"Secure World is not supported!\n");
		return -EPERM;
	}

	if (vcpu->vm->sworld_control.flag.active != 0UL) {
		dev_dbg(ACRN_DBG_TEE_HYCALL,
			"Trusty already initialized!\n");
		return -EPERM;
	}

	if (vcpu->arch.cur_context != NORMAL_WORLD) {
		dev_dbg(ACRN_DBG_TEE_HYCALL,
			"%s, must initialize Trusty from Normal World!\n",
			__func__);
		return -EPERM;
	}

	if (!initialize_tee(vcpu, param)) {
		return -ENODEV;
	}

	vcpu->vm->sworld_control.flag.active = 1UL;

	return 0;
}
