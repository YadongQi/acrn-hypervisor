/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <hypervisor.h>

struct tee_boot_param {
	uint64_t version;
	uint64_t base;
	uint64_t size;
	uint64_t entry_point;
} __aligned(8);

/* Init 32-bit environment for OPTEE */
static void init_tee_env(struct acrn_vcpu *vcpu, uint64_t rip, uint64_t rsp)
{
	struct ext_context *ectx;
	struct run_context *ctx;
	struct segment_sel *seg;
	uint32_t entry_ctls;

	ectx = &(vcpu->arch.contexts[SECURE_WORLD].ext_ctx);
	ctx = &(vcpu->arch.contexts[SECURE_WORLD].run_ctx);

	ctx->cr0 =(1ULL << 18) | (1ULL << 16) | (1ULL << 5) | (1ULL << 4) | (1ULL << 0);
	//ectx->vmx_cr0 = ctx->cr0;
	vcpu_set_cr0(vcpu, ctx->cr0);

	//exec_vmwrite(VMX_CR0_MASK, 0x20);
	//exec_vmwrite(VMX_CR0_READ_SHADOW, 0x11);
	ectx->vmx_cr0 = 0U;
	ectx->vmx_cr0_read_shadow = 0U;
	ectx->vmx_cr4 = 0U;
	ectx->vmx_cr4_read_shadow = 0U;

	vcpu_set_efer(vcpu, 0ULL);

	entry_ctls = exec_vmread32(VMX_ENTRY_CONTROLS);
	entry_ctls &= ~VMX_ENTRY_CTLS_IA32E_MODE;
	exec_vmwrite32(VMX_ENTRY_CONTROLS, entry_ctls);

	ctx->cr4 = (1ULL << 13U);
	//ectx->vmx_cr4 = ctx->cr4;

	vcpu_set_rflags(vcpu, 1ULL << 1);

	vcpu->arch.contexts[SECURE_WORLD].run_ctx.rip = rip;
	vcpu_retain_rip(vcpu);

	vcpu_set_rsp(vcpu, rsp);

	ectx->cs.base = 0UL;
	ectx->cs.limit = 0xFFFFFFFFU;
	ectx->cs.attr = 0xc09bU;
	ectx->cs.selector = 0x08U;

	for (seg = &(ectx->ss); seg <= &(ectx->gs); seg++) {
		seg->base = 0UL;
		seg->limit = 0xFFFFFFFFU;
		seg->attr = 0xc093U;
		seg->selector = 0x10U;
	}

	ectx->tr.base = 0UL;
	ectx->tr.limit = 0xFFFFFFFFU;
	ectx->tr.attr = 0x808bU;
	ectx->tr.selector = 0U;

	ectx->ldtr.base = 0UL;
	ectx->ldtr.limit = 0UL;
	ectx->ldtr.attr = 0x10000U;
	ectx->ldtr.selector = 0U;

	ectx->gdtr.base = 0UL;
	ectx->gdtr.limit = 0x0UL;

	ectx->idtr.base = 0UL;
	ectx->idtr.limit = 0x0UL;
}

bool initialize_tee(struct acrn_vcpu *vcpu, uint64_t param)
{
	struct tee_boot_param boot_param;
	struct acrn_vm *vm = vcpu->vm;

	memset(&boot_param, 0U, sizeof(boot_param));
	if (copy_from_gpa(vcpu->vm, &boot_param, param, sizeof(boot_param))) {
		pr_err("%s: Unable to copy tee boot param\n", __func__);
		return false;
	}

	pr_dbg("%s: v=%llx, b=%llx, s=%llx, e=%llx\n", __func__, boot_param.version, boot_param.base, boot_param.size, boot_param.entry_point);

	/* TODO: create EPTP for Secure World */
	vm->arch_vm.sworld_eptp = vm->arch_vm.nworld_eptp;

	vcpu->arch.contexts[NORMAL_WORLD].run_ctx.cr0 = exec_vmread(VMX_GUEST_CR0);
	vcpu->arch.contexts[NORMAL_WORLD].run_ctx.cr4 = exec_vmread(VMX_GUEST_CR4);
	save_world_ctx(vcpu, &vcpu->arch.contexts[NORMAL_WORLD].ext_ctx);

	vcpu->arch.cur_context = SECURE_WORLD;

	init_tee_env(vcpu, boot_param.entry_point, boot_param.base + boot_param.size);

	load_world_ctx(vcpu, &vcpu->arch.contexts[SECURE_WORLD].ext_ctx);
	exec_vmwrite(VMX_GUEST_CR0, vcpu->arch.contexts[SECURE_WORLD].run_ctx.cr0);
	exec_vmwrite(VMX_GUEST_CR4, vcpu->arch.contexts[SECURE_WORLD].run_ctx.cr4);

	//exec_vmwrite(VMX_EXCEPTION_BITMAP, 0xFFFFFFFF);

	return true;
}
