
#ifndef _TPM_H_
#define _TPM_H_

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
void swtpm_handle_request(TPMBackendCmd *cmd);
int swtpm_startup(size_t buffersize);
size_t swtpm_get_buffer_size(void);
void swtpm_cancel_cmd(void);
int swtpm_stop(void);

/* APIs by tpm_crb.c */
int init_tpm_crb(struct vmctx *ctx);

#endif
