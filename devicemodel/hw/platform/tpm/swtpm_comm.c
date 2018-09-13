/*
 * The module to communicate with swtpm.
 *
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
 * 1. Create UnixSocketAddress to connect to the input path (ctrl channel)
 * and return fd for the socket
 *
 * 2. Call socketpair to create fd0 and fd1, send fd1 to swtpm by using CMD_SET_DATAFD, 
 * using fd0 as the cmd channel, close fd1.
 *
 * 3. CMD_INIT should be sent to swtpm through the ctrl channel to startup tpm
 * emulator. check the return result.
 *
 * 4. Call tpm_util_test_tpmdev to send tpm2 command to swtpm, then check the 
 * return result. (tpm_version_2_0) or use tpm_get_random to test
 *
 * 5. tpm_cleanup should be called.
 * Need to send CMD_SHUTDOWN to swtpm to close it.
 * Need to close the fds for ctrl channel and cmd channel.
 *
 */

#include <sys/un.h>
#include <errno.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <strings.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "vmmapi.h"
#include "tpm.h"

#define TPM_ORD_ContinueSelfTest	0x53
#define PTM_INIT_FLAG_DELETE_VOLATILE	(1 << 0)

#define SWAP_BYTE_16(value)	 (uint16_t) ((value<< 8) | (value>> 8))
#define SWAP_BYTE_32(x)	   ((uint32_t)(\
		(((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#define TPM_TAG_RSP_COMMAND	0xc4
#define TPM_FAIL		9

typedef uint32_t ptm_res;

struct ptm_est {
	union {
		struct {
			ptm_res tpm_result;
			unsigned char bit; /* TPM established bit */
		} resp; /* response */
	} u;
};

struct ptm_reset_est {
	union {
		struct {
			uint8_t loc; /* locality to use */
		} req; /* request */
		struct {
			ptm_res tpm_result;
		} resp; /* response */
	} u;
};

struct ptm_init {
	union {
		struct {
			uint32_t init_flags; /* see definitions below */
		} req; /* request */
		struct {
			ptm_res tpm_result;
		} resp; /* response */
	} u;
};

struct ptm_loc {
	union {
		struct {
			uint8_t loc; /* locality to set */
		} req; /* request */
		struct {
			ptm_res tpm_result;
		} resp; /* response */
	} u;
};

struct ptm_getconfig {
	union {
		struct {
			ptm_res tpm_result;
			uint32_t flags;
		} resp; /* response */
	} u;
};

struct ptm_setbuffersize {
	union {
		struct {
			uint32_t buffersize; /* 0 to query for current buffer size */
		} req; /* request */
		struct {
			ptm_res tpm_result;
			uint32_t buffersize; /* buffer size in use */
			uint32_t minsize; /* min. supported buffer size */
			uint32_t maxsize; /* max. supported buffer size */
		} resp; /* response */
	} u;
};

typedef struct ptm_est ptm_est;
typedef struct ptm_reset_est ptm_reset_est;
typedef struct ptm_loc ptm_loc;
typedef struct ptm_init ptm_init;
typedef struct ptm_getconfig ptm_getconfig;
typedef struct ptm_setbuffersize ptm_setbuffersize;

#pragma pack(push, 1)
typedef struct  {
	uint16_t  tag;
	uint32_t  length;
	uint32_t  ordinal;
} tpm_input_header;

typedef struct  {
	uint16_t  tag;
	uint32_t  length;
	uint32_t  return_code;
} tpm_output_header;
#pragma pack(pop)

typedef struct swtpm_instance {
	int ctrl_chan_fd;
	int cmd_chan_fd;
	uint8_t cur_locty_number; /* last set locality */
	unsigned int established_flag:1;
	unsigned int established_flag_cached:1;
} swtpm_instance;

enum {
	CMD_GET_CAPABILITY = 1,		/* 0x01 */
	CMD_INIT,			/* 0x02 */
	CMD_SHUTDOWN,			/* 0x03 */
	CMD_GET_TPMESTABLISHED,		/* 0x04 */
	CMD_SET_LOCALITY,		/* 0x05 */
	CMD_HASH_START,			/* 0x06 */
	CMD_HASH_DATA,			/* 0x07 */
	CMD_HASH_END,			/* 0x08 */
	CMD_CANCEL_TPM_CMD,		/* 0x09 */
	CMD_STORE_VOLATILE,		/* 0x0a */
	CMD_RESET_TPMESTABLISHED,	/* 0x0b */
	CMD_GET_STATEBLOB,		/* 0x0c */
	CMD_SET_STATEBLOB,		/* 0x0d */
	CMD_STOP,			/* 0x0e */
	CMD_GET_CONFIG,			/* 0x0f */
	CMD_SET_DATAFD,			/* 0x10 */
	CMD_SET_BUFFERSIZE,		/* 0x11 */
	CMD_GET_INFO,			/* 0x12 */
};

static swtpm_instance tpm_inst;

int sv[2] = {-1, -1};

	
static inline uint16_t tpm_cmd_get_tag(const void *b)
{
	return SWAP_BYTE_16(*(uint16_t*)(b));
}

static inline uint32_t tpm_cmd_get_size(const void *b)
{
	return SWAP_BYTE_32(*(uint32_t*)(b + 2));
}

static inline uint32_t tpm_cmd_get_ordinal(const void *b)
{
	return SWAP_BYTE_32(*(uint32_t*)(b + 6));
}

static inline uint32_t tpm_cmd_get_errcode(const void *b)
{
	return SWAP_BYTE_32(*(uint32_t*)(b + 6));
}

static inline void tpm_cmd_set_tag(void *b, uint16_t tag)
{
	*(uint16_t*)(b) = SWAP_BYTE_16(tag);
}

static inline void tpm_cmd_set_size(void *b, uint32_t size)
{
	*(uint32_t*)(b + 2) = SWAP_BYTE_32(size);
}

static inline void tpm_cmd_set_error(void *b, uint32_t error)
{
	*(uint32_t*)(b + 6) = SWAP_BYTE_32(error);
}

bool tpm_is_selftest(const uint8_t *in, uint32_t in_len)
{
	if (in_len >= sizeof(tpm_input_header)) {
		return tpm_cmd_get_ordinal(in) == TPM_ORD_ContinueSelfTest;
	}

	return false;
}

int ctrl_chan_conn(const char *servername)
{
	int clifd;
	struct sockaddr_un servaddr;
	int ret;

	clifd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (clifd < 0) {
		printf("socket failed.\n");
		return -1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	if (!servername) {
		return -1;
	}

	strcpy(servaddr.sun_path, servername);

	ret = connect(clifd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (ret < 0) {
		printf("connect failed.\n");
		return -1;
	}

	return clifd;
}

void ctrl_chan_close(int fd)
{
	close(fd);
}

int ctrl_chan_write(int ctrl_chan_fd, const uint8_t *buf, int len,
			int *pdatafd, int fd_num)
{
	int ret;
	struct msghdr msg;
	struct iovec iov[1];
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *pcmsg;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	iov[0].iov_base = (void*)buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if (!pdatafd && (fd_num == 0)) {
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	} else if (fd_num == 1) {
		msg.msg_control = control_un.control;
		msg.msg_controllen = sizeof(control_un.control);

		pcmsg = CMSG_FIRSTHDR(&msg);
		pcmsg->cmsg_len = CMSG_LEN(sizeof(int));
		pcmsg->cmsg_level = SOL_SOCKET;
		pcmsg->cmsg_type = SCM_RIGHTS;
		*((int *)CMSG_DATA(pcmsg)) = *pdatafd;
	} else {
		printf("fd_num failed.\n");
		return -1;
	}

	do {
		ret = sendmsg(ctrl_chan_fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		fprintf(stderr, "Failed to send msg, reason: %s\n", strerror(errno));
	}

	return ret;
}

int ctrl_chan_read(int ctrl_chan_fd, uint8_t *buf, int len)
{
	struct msghdr msg;
	struct iovec iov[1];
	int recvd = 0;
	int n;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	/* No need to recv fd */
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	while (recvd < len) {
		if (0 == recvd)
			n = recvmsg(ctrl_chan_fd, &msg, 0);
		else
			n = read(ctrl_chan_fd, msg.msg_iov[0].iov_base + recvd, len - recvd);
		if (n <= 0)
			return n;
		recvd += n;
	}

	return recvd;
}

int cmd_chan_write(int cmd_chan_fd, const uint8_t *buf, int len)
{
	ssize_t	 nwritten = 0;
	int buffer_length = len;

	while (buffer_length > 0) {
		nwritten = write(cmd_chan_fd, buf, buffer_length);
		if (nwritten >= 0) {
			buffer_length -= nwritten;
			buf += nwritten;
		}
		else {
			fprintf(stderr, "cmd_chan_write: Error, write() %d %s\n",
					  errno, strerror(errno));
			return -1;
		}
	}

	return (len - buffer_length);
}

int cmd_chan_read(int cmd_chan_fd, uint8_t *buf, int len)
{
	ssize_t nread = 0;
	size_t nleft = len;

	while (nleft > 0) {
		nread = read(cmd_chan_fd, buf, nleft);
		if (nread > 0) {
			nleft -= nread;
			buf += nread;
		}
		else if (nread < 0) {/* error */
			fprintf(stderr, "cmd_chan_read: Error, read() error %d %s\n",
				   errno, strerror(errno));
			return -1;
		}
		else if (nread == 0) {/* EOF */
			fprintf(stderr, "cmd_chan_read: Error, read EOF, read %lu bytes\n",
				   (unsigned long)(len - nleft));
			return -1;
		}
	}

	return (len - nleft);
}

static int swtpm_ctrlcmd(int ctrl_chan_fd, unsigned long cmd, void *msg,
			size_t msg_len_in, size_t msg_len_out,
			int *pdatafd, int fd_num)
{
	uint32_t cmd_no = SWAP_BYTE_32(cmd);
	ssize_t n = sizeof(uint32_t) + msg_len_in;
	uint8_t *buf = NULL;
	int ret = -1;
	int send_num;
	int recv_num;

	buf = calloc(n, sizeof(char));
	memcpy(buf, &cmd_no, sizeof(cmd_no));
	memcpy(buf + sizeof(cmd_no), msg, msg_len_in);

	send_num = ctrl_chan_write(ctrl_chan_fd, buf, n, pdatafd, fd_num);
	if ((send_num <= 0) || (send_num != n) ) {
		goto end;
	}

	if (msg_len_out != 0) {
		recv_num = ctrl_chan_read(ctrl_chan_fd, msg, msg_len_out);
		if ((recv_num <= 0) || (recv_num != msg_len_out)) {
			goto end;
		}
	}

	ret = 0;

end:
	free(buf);
	return ret;
}

static int swtpm_cmdcmd(int cmd_chan_fd,
			const uint8_t *in, uint32_t in_len,
			uint8_t *out, uint32_t out_len, bool *selftest_done)
{
	ssize_t ret;
	bool is_selftest = false;

	if (selftest_done) {
		*selftest_done = false;
		is_selftest = tpm_is_selftest(in, in_len);
	}

	ret = cmd_chan_write(cmd_chan_fd, (uint8_t *)in, in_len);
	if ((ret == -1) || (ret != in_len)) {
		return -1;
	}

	ret = cmd_chan_read(cmd_chan_fd, (uint8_t *)out,
			  sizeof(tpm_output_header));
	if (ret == -1) {
		return -1;
	}

	ret = cmd_chan_read(cmd_chan_fd,
				(uint8_t *)out + sizeof(tpm_output_header),
				tpm_cmd_get_size(out) - sizeof(tpm_output_header));
	if (ret == -1) {
		return -1;
	}

	if (is_selftest) {
		*selftest_done = tpm_cmd_get_errcode(out) == 0;
	}

	return 0;
}

static int swtpm_ctrlchan_create(const char *arg_path)
{
	int connfd;
	connfd = ctrl_chan_conn(arg_path);
	if(connfd<0)
	{
		printf("Error[%d] when connecting...",errno);
		return -1;
	}

	tpm_inst.ctrl_chan_fd = connfd;

	return connfd;
}

static int swtpm_cmdchan_create(void)
{
	ptm_res res;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
	{
		printf("socketpair failed!\n");
		return -1;
	}
	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_SET_DATAFD, &res, 0,
				 sizeof(res), &sv[1], 1) < 0 || res != 0) {
		printf("swtpm: Failed to send CMD_SET_DATAFD: %s", strerror(errno));
		goto err_exit;
	}
	tpm_inst.cmd_chan_fd = sv[0];
	close(sv[1]);

	return 0;

err_exit:
	close(sv[0]);
	close(sv[1]);
	return -1;
}

int swtpm_stop(void)
{
	ptm_res res;

	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_STOP, &res, 0, sizeof(res), NULL, 0) < 0) {
		printf("swtpm: Could not stop TPM: %s",
		strerror(errno));
		return -1;
	}

	res = SWAP_BYTE_32(res);
	if (res) {
		printf("swtpm: TPM result for CMD_STOP: 0x%x", res);
		return -1;
	}

	return 0;
}

static int swtpm_set_buffer_size(size_t wanted_size,
					size_t *actual_size)
{
	ptm_setbuffersize psbs;

	if (swtpm_stop() < 0) {
		return -1;
	}

	psbs.u.req.buffersize = SWAP_BYTE_32(wanted_size);

	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_SET_BUFFERSIZE, &psbs,
			 sizeof(psbs.u.req), sizeof(psbs.u.resp), NULL, 0) < 0) {
		printf("swtpm: Could not set buffer size: %s", strerror(errno));
		return -1;
	}

	psbs.u.resp.tpm_result = SWAP_BYTE_32(psbs.u.resp.tpm_result);
	if (psbs.u.resp.tpm_result != 0) {
		printf("swtpm: TPM result for set buffer size : 0x%x", psbs.u.resp.tpm_result);
		return -1;
	}

	if (actual_size) {
		*actual_size = SWAP_BYTE_32(psbs.u.resp.buffersize);
	}

	return 0;
}

static int swtpm_startup_tpm_resume(size_t buffersize,
					bool is_resume)
{
	ptm_init init = {
		.u.req.init_flags = 0,
	};
	ptm_res res;

	if (buffersize != 0 &&
		swtpm_set_buffer_size(buffersize, NULL) < 0) {
		goto err_exit;
	}

	if (is_resume) {
		init.u.req.init_flags |= SWAP_BYTE_32(PTM_INIT_FLAG_DELETE_VOLATILE);
	}

	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_INIT,
					&init, sizeof(init), sizeof(init), NULL, 0) < 0) {
		printf("swtpm: could not send INIT: %s",
		strerror(errno));
		goto err_exit;
	}

	res = SWAP_BYTE_32(init.u.resp.tpm_result);
	if (res) {
		printf("swtpm: TPM result for CMD_INIT: 0x%x", res);
		goto err_exit;
	}

	return 0;

err_exit:
	return -1;
}

int swtpm_startup(size_t buffersize)
{
	return swtpm_startup_tpm_resume(buffersize, false);
}

static void swtpm_shutdown(void)
{
	ptm_res res;

	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_SHUTDOWN,
					&res, 0, sizeof(res), NULL, 0) < 0) {
		printf("swtpm: Could not cleanly shutdown the TPM: %s", strerror(errno));
	} else if (res != 0) {
		printf("swtpm: TPM result for sutdown: 0x%x", SWAP_BYTE_32(res));
	}
}

void swtpm_cleanup(void)
{
	swtpm_shutdown();
	close(tpm_inst.cmd_chan_fd);
	close(tpm_inst.ctrl_chan_fd);
}

static int swtpm_set_locality(uint8_t locty_number)
{
	ptm_loc loc;

	if (tpm_inst.cur_locty_number == locty_number) {
		return 0;
	}

	loc.u.req.loc = locty_number;
	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_SET_LOCALITY, &loc,
							 sizeof(loc), sizeof(loc), NULL, 0) < 0) {
		printf("swtpm: could not set locality : %s", strerror(errno));
		return -1;
	}

	loc.u.resp.tpm_result = SWAP_BYTE_32(loc.u.resp.tpm_result);
	if (loc.u.resp.tpm_result != 0) {
		printf("swtpm: TPM result for set locality : 0x%x", loc.u.resp.tpm_result);
		return -1;
	}

	tpm_inst.cur_locty_number = locty_number;

	return 0;
}

void swtpm_write_fatal_error_response(uint8_t *out, uint32_t out_len)
{
	if (out_len >= sizeof(tpm_output_header)) {
		tpm_cmd_set_tag(out, TPM_TAG_RSP_COMMAND);
		tpm_cmd_set_size(out, sizeof(tpm_output_header));
		tpm_cmd_set_error(out, TPM_FAIL);
	}
}

int swtpm_handle_request(TPMBackendCmd *cmd)
{
	if (swtpm_set_locality(cmd->locty) < 0 ||
		swtpm_cmdcmd(tpm_inst.cmd_chan_fd, cmd->in, cmd->in_len,
				cmd->out, cmd->out_len,
				&cmd->selftest_done) < 0) {
		swtpm_write_fatal_error_response(cmd->out, cmd->out_len);
		return -1;
	}
	return 0;
}

bool swtpm_get_tpm_established_flag(void)
{
	ptm_est est;

	if (tpm_inst.established_flag_cached) {
		return tpm_inst.established_flag;
	}

	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_GET_TPMESTABLISHED, &est,
				0, sizeof(est), NULL, 0) < 0) {
		printf("swtpm: Could not get the TPM established flag: %s", strerror(errno));
		return false;
	}

	tpm_inst.established_flag_cached = 1;
	tpm_inst.established_flag = (est.u.resp.bit != 0);

	return tpm_inst.established_flag;
}

int swtpm_reset_tpm_established_flag(void)
{
	ptm_reset_est reset_est;
	ptm_res res;

	reset_est.u.req.loc = tpm_inst.cur_locty_number;
	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_RESET_TPMESTABLISHED,
				&reset_est, sizeof(reset_est),
				sizeof(reset_est), NULL, 0) < 0) {
		printf("swtpm: Could not reset the establishment bit: %s",
		strerror(errno));
		return -1;
	}

	res = SWAP_BYTE_32(reset_est.u.resp.tpm_result);
	if (res) {
		printf("swtpm: TPM result for rest establixhed flag: 0x%x", res);
		return -1;
	}

	tpm_inst.established_flag_cached = 0;

	return 0;
}

void swtpm_cancel_cmd(void)
{
	ptm_res res;

	if (swtpm_ctrlcmd(tpm_inst.ctrl_chan_fd, CMD_CANCEL_TPM_CMD, &res, 0,
				sizeof(res), NULL, 0) < 0) {
		printf("swtpm: Could not cancel command: %s", strerror(errno));
	} else if (res != 0) {
		printf("swtpm: Failed to cancel TPM: 0x%x", SWAP_BYTE_32(res));
	}
}

size_t swtpm_get_buffer_size(void)
{
	size_t actual_size;

	if (swtpm_set_buffer_size(0, &actual_size) < 0) {
		return 4096;
	}

	return actual_size;
}

void init_tpm_emulator(const char *sock_path)
{
	assert(sock_path);

	swtpm_ctrlchan_create(sock_path);
	swtpm_cmdchan_create();
}
