#pragma once

#include <stdint.h>

enum SSHErrorCode
{
	ERR_SSH_SUCCESS = 0,
	ERR_SSH_FAILURE = -1,
	ERR_SSH_ABORT = -2,
	ERR_SSH_REFUSE = -3,
	ERR_SSH_BUSY = -4,
	ERR_SSH_IO_ERROR = -5,
};

enum SSHStatus
{
	STAT_SSH_CONNECTED,
	STAT_SSH_DISCONNECTED,
};

struct SFTP_FILE_INFO 
{
	uint32_t flags;
	uint64_t filesize;
	uint32_t uid;
	uint32_t gid;
	uint32_t permissions;
	uint32_t atime;
	uint32_t mtime;
	char	 filename[256];
};

class ISSHConnector
{
public:
	// auth
	virtual int32_t connect(const char* username, const char* password, const char* host = nullptr, uint16_t port = 22) = 0;

	virtual SSHStatus status() const = 0;

	virtual void disconnect() = 0;

	virtual char* error() = 0;

	// ssh
	virtual int32_t exec(const char* commandline, char* out = nullptr, int32_t* outsize = nullptr,
		char* err = nullptr, int32_t* errsize = nullptr, int32_t outfd = -1, int32_t errfd = -1) = 0;

	// sftp
	virtual int32_t sftp_open(const char* path, int32_t flag, int32_t mode = 0755) = 0;

	virtual int32_t sftp_close() = 0;

	virtual int32_t sftp_read(char* buffer, int32_t size) = 0;

	virtual int32_t sftp_write(const char* buffer, int32_t size) = 0;

	//
	virtual int32_t sftp_open_dir(const char* path) = 0;

	virtual int32_t sftp_close_dir() = 0;

	virtual int32_t sftp_unlink(const char* path) = 0;

	virtual int32_t sftp_mkdir(const char* path, int32_t mode) = 0;

	virtual int32_t sftp_rmdir(const char* path) = 0;

	virtual SFTP_FILE_INFO* sftp_read_dir() = 0;

	virtual SFTP_FILE_INFO* sftp_stat(const char* path) = 0;

	virtual SFTP_FILE_INFO* sftp_lstat(const char* path) = 0;

	virtual int32_t sftp_setstat(const char* path, SFTP_FILE_INFO* attrs) = 0;

	virtual char* sftp_readlink(const char* path) = 0;
	
	virtual int32_t sftp_symlink(const char* path, const char* link) = 0;
	
	virtual char* sftp_realpath(const char* path) = 0;

	// local->remote
	virtual int32_t sftp_copy_file(const char* local, const char* remote) = 0;

	virtual int32_t sftp_copy_link(const char* local, const char* remote) = 0;

	virtual int32_t sftp_copy_dir(const char* local, const char* remote) = 0;

	virtual int32_t sftp_copy(const char* local, const char* remote) = 0;

	// other
	virtual int32_t chown(const char* remote, const char* user, const char* group) = 0;

	virtual int32_t chmod(const char* remote, int32_t mode = 0755) = 0;

	virtual int32_t send_file(const char* local, const char* remote, int32_t keep_owner = 0) = 0;

	virtual int32_t recv_file(const char* local, const char* remote) = 0;

};

