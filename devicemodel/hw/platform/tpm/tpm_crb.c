#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "vmmapi.h"
#include "inout.h"
#include "mem.h"
#include "tpm.h"

#define __packed __attribute__((packed))

#define CRB_LOC_CTRL_REQUEST_ACCESS      (1U << 0U)
#define CRB_LOC_CTRL_RELINQUISH          (1U << 1U)
#define CRB_LOC_CTRL_SEIZE               (1U << 2U)
#define CRB_LOC_CTRL_RESET_ESTABLISHMENT (1U << 3U)

#define CRB_CTRL_REQ_CMD_READY (1U << 0U)
#define CRB_CTRL_REQ_CMD_IDLE  (1U << 1U)

#define CRB_CTRL_CANCEL_CMD     0x00000001U
#define CRB_CTRL_CMD_CANCELLED  0x00000000U

#define CRB_CTRL_START_CMD     0x00000001U
#define CRB_CTRL_CMD_COMPLETED 0x00000000U

struct locality_state {
	uint32_t tpmEstablished : 1;
	uint32_t locAssigned    : 1;
	uint32_t activeLocality : 3;
	uint32_t reserved0      : 2;
	uint32_t tpmRegValidSts : 1;
	uint32_t reserved1      : 24;
} __packed;

struct locality_ctrl {
	uint32_t requestAccess         : 1;
	uint32_t relinquish            : 1;
	uint32_t seize                 : 1;
	uint32_t resetEstablishmentBit : 1;
	uint32_t reserved              : 28;
} __packed;

struct locality_sts {
	uint32_t granted    : 1;
	uint32_t beenSeized : 1;
	uint32_t reserved   : 30;
} __packed;

struct interface_identifier {
	struct {
		uint32_t interfaceType          : 4;
		uint32_t interfaceVersion       : 4;
		uint32_t capLocality            : 1;
		uint32_t capCRBIdleBypass       : 1;
		uint32_t reserved0              : 1;
		uint32_t capDataXferSizeSupport : 2;
		uint32_t capFIFO                : 1;
		uint32_t capCRB                 : 1;
		uint32_t capIFRes               : 2;
		uint32_t interfaceSelector      : 2;
		uint32_t intfSelLock            : 1;
		uint32_t reserved1              : 4;
		uint32_t RID                    : 8;
	} lo __packed;

	struct {
		uint32_t VID : 16;
		uint32_t DID : 16;
	} hi __packed;
} __packed;

struct control_area_ext {
	uint32_t clear;
	uint32_t remaining_bytes;
} __packed;

struct control_area_req {
	uint32_t cmdReady : 1;
	uint32_t goIdle   : 1;
	uint32_t reserved : 30;
} __packed;

struct control_area_sts {
	uint32_t tpmSts   : 1;
	uint32_t tpmIdle  : 1;
	uint32_t reserved : 30;
} __packed;

struct interrupt_enable {
	uint32_t startIntEnable              : 1;
	uint32_t cmdReadyIntEnable           : 1;
	uint32_t establishmentClearIntEnable : 1;
	uint32_t localityChangeIntEnable     : 1;
	uint32_t reserved                    : 27;
	uint32_t globalInterruptEnable       : 1;
} __packed;

struct interrupt_status {
	uint32_t startInt              : 1;
	uint32_t cmdReadyInt           : 1;
	uint32_t establishmentClearInt : 1;
	uint32_t localityChangeInt     : 1;
	uint32_t reserved              : 28;
} __packed;

struct crb_reg_space {
	union {
		struct {
			struct locality_state loc_state;
			uint32_t reserved0;
			struct locality_ctrl loc_ctrl;
			struct locality_sts loc_sts;
			uint32_t reserved1[8];
			struct interface_identifier intf_id;
			struct control_area_ext ctrl_ext;
			struct control_area_req ctrl_req;
			struct control_area_sts ctrl_sts;
			uint32_t ctrl_cancel;
			uint32_t ctrl_start;
			struct interrupt_enable int_enable;
			struct interrupt_status int_status;
			uint32_t ctrl_cmd_size;
			uint32_t ctrl_cmd_addr_lo;
			uint32_t ctrl_cmd_addr_hi;
			uint32_t ctrl_rsp_size;
			uint64_t ctrl_rsp_addr;
		};
		uint8_t bytes[CRB_DATA_BUFFER_OFF];
	} regs;
} __packed;

struct tpm_crb_vdev {
	struct crb_reg_space crb_regs;
	uint8_t data_buffer[TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER_OFF];
	size_t be_buffer_size;
};

static uint64_t mmio_read(void *addr, int size)
{
	uint64_t val = 0;
	switch (size) {
	case 1:
		val = *(uint8_t *)addr;
		break;
	case 2:
		val = *(uint16_t *)addr;
		break;
	case 4:
		val = *(uint32_t *)addr;
		break;
	case 8:
		val = *(uint64_t *)addr;
		break;
	}
	return val;
}

static void mmio_write(void *addr, int size, uint64_t val)
{
	switch (size) {
	case 1:
		*(uint8_t *)addr = val;
		break;
	case 2:
		*(uint16_t *)addr = val;
		break;
	case 4:
		*(uint32_t *)addr = val;
		break;
	case 8:
		*(uint64_t *)addr = val;
		break;
	}
}

static uint64_t crb_reg_read(void *vdev, uint64_t addr, int size)
{
	struct tpm_crb_vdev *tpm_vdev;
	uint32_t val;
	uint64_t off;

	tpm_vdev = (struct tpm_crb_vdev *)vdev;
	off = (addr & ~3UL) - TPM_CRB_MMIO_ADDR;

	val = mmio_read(&tpm_vdev->crb_regs.regs.bytes[off], size);

	if (off == CRB_REGS_LOC_STATE_OFF) {
		val |= !swtpm_get_tpm_established_flag();
	}

	return val;
}

static void clear_data_buffer(struct tpm_crb_vdev *vdev)
{
	memset(vdev->data_buffer, 0, sizeof(vdev->data_buffer));
}

static uint8_t get_active_locality(struct tpm_crb_vdev *vdev)
{
	if (vdev->crb_regs.regs.loc_state.locAssigned == 0) {
		return 0xFF;
	}

	return vdev->crb_regs.regs.loc_state.activeLocality;
}

static uint32_t get_tpm_cmd_size(void *data_buffer)
{
	/*
	 * The command header is formated by:
	 *     tag    (2 bytes): 80 01
	 *     length (4 bytes): 00 00 00 00
	 *     ordinal(4 bytes): 00 00 00 00
	 */
	return be32dec(data_buffer + 2);
}

/* TODO: this function is designed for emulator thread to complet the command,
 * currently, directly call it after handle request. */
void tpm_crb_request_completed(struct tpm_crb_vdev *vdev, int err)
{
	vdev->crb_regs.regs.ctrl_start = CRB_CTRL_CMD_COMPLETED;
	if (err) {
		/* Fatal error */
		vdev->crb_regs.regs.ctrl_sts.tpmSts = 0b1;
	}
}

static void crb_reg_write(void *vdev, uint64_t addr, int size, uint64_t val)
{
	struct tpm_crb_vdev *tpm_vdev;
	uint64_t off;
	uint8_t target_loc = (addr >> 12) & 0b111;
	uint32_t cmd_size;
	TPMBackendCmd cmd;

	tpm_vdev = (struct tpm_crb_vdev *)vdev;
	off = addr - TPM_CRB_MMIO_ADDR;

	switch (off) {
	case CRB_REGS_CTRL_REQ_OFF:
		switch (val) {
		case CRB_CTRL_REQ_CMD_READY:
			tpm_vdev->crb_regs.regs.ctrl_sts.tpmIdle = 0;
			break;
		case CRB_CTRL_REQ_CMD_IDLE:
			clear_data_buffer(tpm_vdev);
			tpm_vdev->crb_regs.regs.ctrl_sts.tpmIdle = 1;
			break;
		}
		break;
	case CRB_REGS_CTRL_CANCEL_OFF:
		if ((val == CRB_CTRL_CANCEL_CMD) &&
			(tpm_vdev->crb_regs.regs.ctrl_start == CRB_CTRL_START_CMD)) {
			swtpm_cancel_cmd();
		}
		break;
	case CRB_REGS_CTRL_START_OFF:
		if ((val == CRB_CTRL_START_CMD) &&
			(tpm_vdev->crb_regs.regs.ctrl_start != CRB_CTRL_START_CMD) &&
			(get_active_locality(vdev) == target_loc)) {

			tpm_vdev->crb_regs.regs.ctrl_start = CRB_CTRL_START_CMD;
			cmd_size = MIN(get_tpm_cmd_size(tpm_vdev->data_buffer),
					TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER_OFF);

			cmd.locty = 0;
			cmd.in = &tpm_vdev->data_buffer[0];
			cmd.in_len = cmd_size;
			cmd.out = &tpm_vdev->data_buffer[0];
			cmd.out_len = tpm_vdev->be_buffer_size;

			swtpm_handle_request(&cmd);
			tpm_crb_request_completed(tpm_vdev, 0);
		}
		break;
	case CRB_REGS_LOC_CTRL_OFF:
		switch (val) {
		case CRB_LOC_CTRL_RESET_ESTABLISHMENT:
			break;
		case CRB_LOC_CTRL_RELINQUISH:
			tpm_vdev->crb_regs.regs.loc_state.locAssigned = 0;
			tpm_vdev->crb_regs.regs.loc_sts.granted = 0;
			break;
		case CRB_LOC_CTRL_REQUEST_ACCESS:
			tpm_vdev->crb_regs.regs.loc_sts.granted = 1;
			tpm_vdev->crb_regs.regs.loc_sts.beenSeized = 0;
			tpm_vdev->crb_regs.regs.loc_state.locAssigned = 1;
			break;
		}
		break;
	}
}

static int tpm_crb_reg_handler(struct vmctx *ctx, int vcpu, int dir, uint64_t addr,
		int size, uint64_t *val, void *arg1, long arg2)
{
	if (dir == MEM_F_READ) {
		*val = crb_reg_read(arg1, addr, size);
	} else {
		crb_reg_write(arg1, addr, size, *val);
	}

	return 0;
}

static int tpm_crb_data_buffer_handler(struct vmctx *ctx, int vcpu, int dir, uint64_t addr,
		int size, uint64_t *val, void *arg1, long arg2)
{
	struct tpm_crb_vdev *tpm_vdev;
	uint64_t off;

	tpm_vdev = (struct tpm_crb_vdev *)arg1;
	off = addr - TPM_CRB_MMIO_ADDR - CRB_DATA_BUFFER_OFF;

	if (dir == MEM_F_READ) {
		*val = mmio_read(&tpm_vdev->data_buffer[off], size);
	} else {
		mmio_write(&tpm_vdev->data_buffer[off], size, *val);
	}

	return 0;
}

#define CRB_INTF_ID_TYPE_CRB_ACTIVE     0b0001
#define CRB_INTF_VERSION                0b0001
#define CRB_INTF_CAP_LOC_0_ONLY         0b0
#define CRB_INTF_CAP_FAST_IDLE          0b0
#define CRB_INTF_CAP_DATAXFER_SIZE_64   0b11
#define CRB_INTF_CAP_FIFO_NOT_SUPPORTED 0b0
#define CRB_INTF_CAP_CRB_SUPPORTED      0b1
#define CRB_INTF_CAP_INTERFACE_SEL_CRB  0b01
#define CRB_INTF_REVISION_ID            0b0000
#define CRB_INTF_VENDOR_ID              0x8086
static void tpm_crb_reset(void *dev)
{
	struct tpm_crb_vdev *tpm_vdev = (struct tpm_crb_vdev *)dev;
	/* TODO: Finish sync */

	memset(&tpm_vdev->crb_regs, 0, sizeof(tpm_vdev->crb_regs));

	tpm_vdev->crb_regs.regs.loc_state.tpmRegValidSts = 1U;
	tpm_vdev->crb_regs.regs.ctrl_sts.tpmIdle = 1U;
	tpm_vdev->crb_regs.regs.intf_id.lo.interfaceType = CRB_INTF_ID_TYPE_CRB_ACTIVE;
	tpm_vdev->crb_regs.regs.intf_id.lo.interfaceVersion = CRB_INTF_VERSION;
	tpm_vdev->crb_regs.regs.intf_id.lo.capLocality = CRB_INTF_CAP_LOC_0_ONLY;
	tpm_vdev->crb_regs.regs.intf_id.lo.capCRBIdleBypass = CRB_INTF_CAP_FAST_IDLE;
	tpm_vdev->crb_regs.regs.intf_id.lo.capDataXferSizeSupport = CRB_INTF_CAP_DATAXFER_SIZE_64;
	tpm_vdev->crb_regs.regs.intf_id.lo.capFIFO = CRB_INTF_CAP_FIFO_NOT_SUPPORTED;
	tpm_vdev->crb_regs.regs.intf_id.lo.capCRB = CRB_INTF_CAP_CRB_SUPPORTED;
	tpm_vdev->crb_regs.regs.intf_id.lo.interfaceSelector = CRB_INTF_CAP_INTERFACE_SEL_CRB;
	tpm_vdev->crb_regs.regs.intf_id.lo.RID = CRB_INTF_REVISION_ID;
	tpm_vdev->crb_regs.regs.intf_id.hi.VID = CRB_INTF_VENDOR_ID;

	tpm_vdev->crb_regs.regs.ctrl_cmd_size = TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER_OFF;
	tpm_vdev->crb_regs.regs.ctrl_cmd_addr_lo = TPM_CRB_MMIO_ADDR + CRB_DATA_BUFFER_OFF;
	tpm_vdev->crb_regs.regs.ctrl_rsp_size = TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER_OFF;
	tpm_vdev->crb_regs.regs.ctrl_rsp_addr = TPM_CRB_MMIO_ADDR + CRB_DATA_BUFFER_OFF;

	tpm_vdev->be_buffer_size = swtpm_get_buffer_size();

	/* Emulator startup */
	swtpm_startup(0);
	swtpm_stop();
	swtpm_startup(TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER_OFF);
}

void init_tpm_crb(struct vmctx *ctx)
{
	struct mem_range mr;
	int error;
	struct tpm_crb_vdev *tpm_vdev;

	tpm_vdev = calloc(1, sizeof(struct tpm_crb_vdev));

	assert(tpm_vdev != NULL);
	ctx->tpm_dev = tpm_vdev;

	mr.name = "tpm_crb_reg";
	mr.base = TPM_CRB_MMIO_ADDR;
	mr.size = CRB_DATA_BUFFER_OFF;
	mr.flags = MEM_F_RW;
	mr.handler = tpm_crb_reg_handler;
	mr.arg1 = tpm_vdev;
	mr.arg2 = 0;

	error = register_mem(&mr);
	assert(error == 0);

	mr.name = "tpm_crb_buffer";
	mr.base = TPM_CRB_MMIO_ADDR + CRB_DATA_BUFFER_OFF;
	mr.size = TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER_OFF;
	mr.flags = MEM_F_RW;
	mr.handler = tpm_crb_data_buffer_handler;
	mr.arg1 = tpm_vdev;
	mr.arg2 = 0;

	error = register_mem(&mr);
	assert(error == 0);

	tpm_crb_reset(tpm_vdev);
}

void deinit_tpm_crb(struct vmctx *ctx)
{
	struct mem_range mr;

	mr.name = "tpm_crb_reg";
	mr.base = TPM_CRB_MMIO_ADDR;
	mr.size = CRB_DATA_BUFFER_OFF;
	mr.flags = MEM_F_RW;
	mr.handler = tpm_crb_reg_handler;
	mr.arg1 = ctx->tpm_dev;
	mr.arg2 = 0;
	unregister_mem(&mr);

	mr.name = "tpm_crb_buffer";
	mr.base = TPM_CRB_MMIO_ADDR + CRB_DATA_BUFFER_OFF;
	mr.size = TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER_OFF;
	mr.flags = MEM_F_RW;
	mr.handler = tpm_crb_data_buffer_handler;
	mr.arg1 = ctx->tpm_dev;
	mr.arg2 = 0;
	unregister_mem(&mr);

	swtpm_stop();

	if (ctx->tpm_dev)
		free(ctx->tpm_dev);
}
