#pragma once

#include <string>
#include "libssh2_config.h"
#include "libssh2.h"
#include "libssh2_sftp.h"
#include "isshconnector.h"

typedef uint32_t uid_t;
typedef uint32_t gid_t;

class SSHConnector : public ISSHConnector
{
public:
	SSHConnector();
	~SSHConnector();

	virtual int32_t connect(const char* username, const char* password, const char* host = nullptr, uint16_t port = 22) override;

	virtual SSHStatus status() const override;

	virtual void disconnect() override;

	virtual char* error() override;

	// ssh
	virtual int32_t exec(const char* commandline, char* out = nullptr, int32_t* outsize = nullptr,
		char* err = nullptr, int32_t* errsize = nullptr, int32_t outfd = -1, int32_t errfd = -1) override;

	// sftp
	virtual int32_t sftp_open(const char* path, int32_t flag, int32_t mode = 0755) override;

	virtual int32_t sftp_close() override;

	virtual int32_t sftp_read(char* buffer, int32_t size) override;

	virtual int32_t sftp_write(const char* buffer, int32_t size) override;

	//
	virtual int32_t sftp_open_dir(const char* path) override;

	virtual int32_t sftp_close_dir() override;

	virtual SFTP_FILE_INFO* sftp_read_dir() override;

	virtual int32_t sftp_unlink(const char* path) override;

	virtual int32_t sftp_mkdir(const char* path, int32_t mode) override;

	virtual int32_t sftp_rmdir(const char* path) override;

	virtual SFTP_FILE_INFO* sftp_stat(const char* path) override;

	virtual SFTP_FILE_INFO* sftp_lstat(const char* path) override;

	virtual int32_t sftp_setstat(const char* path, SFTP_FILE_INFO* attrs) override;

	virtual char* sftp_readlink(const char* path) override;

	virtual int32_t sftp_symlink(const char* path, const char* link) override;

	virtual char* sftp_realpath(const char* path) override;

	// local->remote
	virtual int32_t sftp_copy_file(const char* local, const char* remote) override;

	virtual int32_t sftp_copy_link(const char* local, const char* remote) override;

	virtual int32_t sftp_copy_dir(const char* local, const char* remote) override;

	virtual int32_t sftp_copy(const char* local, const char* remote) override;

	// other
	virtual int32_t chown(const char* remote, const char* user, const char* group) override;

	virtual int32_t chmod(const char* remote, int32_t mode = 0755) override;

	virtual int32_t send_file(const char* local, const char* remote, int32_t keep_owner = 0) override;

	virtual int32_t recv_file(const char* local, const char* remote) override;


protected:
	int32_t sftp_init();

	int32_t sftp_shutdown();

	int32_t wait_for_socket(int32_t second = -1);

	void init_attrs(LIBSSH2_SFTP_ATTRIBUTES* attrs, struct stat* st);
	//
	std::string getNameByUid(uid_t uid);

	std::string getNameByGid(gid_t gid);

	std::string getBaseName(const char* path);

	std::string getDirName(const char* path);

	std::string AdjustPath(const char* path);

private:
	int32_t				socket_;
	struct sockaddr_in	sock_addr_;
	//
	SSHStatus			status_;
	//
	LIBSSH2_SFTP*		sftp_;
	LIBSSH2_SESSION*	session_;
	LIBSSH2_SFTP_HANDLE* sftp_handle_;
	//
	char*				cache_;
	int32_t				cache_size_;
	char*				err_msg_;
};

