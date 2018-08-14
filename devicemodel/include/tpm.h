/*
 * Copyright (C) 2018 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer
 * in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Contact Information: weideng <wei.a.deng@intel.com>
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _TPM_H_
#define _TPM_H_

/* TPM CRB registers offset */
enum {
	CRB_REGS_LOC_STATE_OFF       = 0x00,
	CRB_REGS_RESERVED0_OFF       = 0x04,
	CRB_REGS_LOC_CTRL_OFF        = 0x08,
	CRB_REGS_LOC_STS_OFF         = 0x0C,
	CRB_REGS_RESERVED1_OFF       = 0x10,
	CRB_REGS_INTF_ID_LO_OFF      = 0x30,
	CRB_REGS_INTF_ID_HI_OFF      = 0x34,
	CRB_REGS_CTRL_EXT_LO_OFF     = 0x38,
	CRB_REGS_CTRL_EXT_HI_OFF     = 0x3C,
	CRB_REGS_CTRL_REQ_OFF        = 0x40,
	CRB_REGS_CTRL_STS_OFF        = 0x44,
	CRB_REGS_CTRL_CANCEL_OFF     = 0x48,
	CRB_REGS_CTRL_START_OFF      = 0x4C,
	CRB_REGS_CTRL_INT_ENABLE_OFF = 0x50,
	CRB_REGS_CTRL_INT_STS_OFF    = 0x54,
	CRB_REGS_CTRL_CMD_SIZE_OFF   = 0x58,
	CRB_REGS_CTRL_CMD_PA_LO_OFF  = 0x5C,
	CRB_REGS_CTRL_CMD_PA_HI_OFF  = 0x60,
	CRB_REGS_CTRL_RSP_SIZE_OFF   = 0x64,
	CRB_REGS_CTRL_RSP_PA_OFF     = 0x68,
	CRB_DATA_BUFFER_OFF          = 0x80
};

#define TPM_CRB_MMIO_ADDR 0xFED40000UL
#define TPM_CRB_MMIO_SIZE 0x1000U
#define TPM_CRB_CTRL_ADDR (TPM_CRB_MMIO_ADDR + CRB_REGS_CTRL_REQ_OFF)

/* TPMCommBuffer will package TPM2 command and
 * response which are handled by TPM emulator
 *
 * locty: the locality TPM emulator used
 * in & in_len: To indicate the buffer and the
 *    size for TPM command
 * out & out_len: To indicate the buffer and
 *    the size for TPM response
 */
typedef struct TPMCommBuffer {
	uint8_t locty;
	const uint8_t *in;
	uint32_t in_len;
	uint8_t *out;
	uint32_t out_len;
	bool selftest_done;
} TPMCommBuffer;

/* APIs by tpm_emulator.c */
/* Create Ctrl chan and Cmd chan so as to communicate with SWTPM */
void init_tpm_emulator(const char *sock_path);
/* Send Ctrl chan command CMD_GET_TPMESTABLISHED to SWTPM */
bool swtpm_get_tpm_established_flag(void);
/* Send Ctrl chan command CMD_RESET_TPMESTABLISHED to SWTPM */
int swtpm_reset_tpm_established_flag(void);
/* Send TPM2 command request to SWTPM by using Cmd chan */
int swtpm_handle_request(TPMCommBuffer *cmd);
/* Initialization for SWTPM */
int swtpm_startup(size_t buffersize);
/* Shutdown of SWTPM and close Ctrl chan and Cmd chan */
void swtpm_cleanup(void);
/* Cancellation of the current TPM2 command */
void swtpm_cancel_cmd(void);

/* APIs by tpm_crb.c */
void init_tpm_crb(struct vmctx *ctx);
void deinit_tpm_crb(struct vmctx *ctx);

#endif
