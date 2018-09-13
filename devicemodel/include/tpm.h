
#ifndef _TPM_H_
#define _TPM_H_

typedef struct TPMBackendCmd {
	uint8_t locty;
	const uint8_t *in;
	uint32_t in_len;
	uint8_t *out;
	uint32_t out_len;
	bool selftest_done;
} TPMBackendCmd;


/* APIs by swtpm_comm.c */
void init_tpm_emulator(const char *sock_path);
bool swtpm_get_tpm_established_flag(void);
int swtpm_handle_request(TPMBackendCmd *cmd);
int swtpm_startup(size_t buffersize);
size_t swtpm_get_buffer_size(void);
void swtpm_cancel_cmd(void);
int swtpm_stop(void);

#endif
