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

#endif
