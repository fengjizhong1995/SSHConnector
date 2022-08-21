#include "sshconnector.h"
#include <algorithm>
#include <io.h>
#include <ctime>
#include <fcntl.h>
#include "dirent.h"

const int32_t ConstCacheSize = 4096;

SSHConnector::SSHConnector()
{
	socket_ = -1;
	sftp_ = nullptr;
	session_ = nullptr;
	cache_size_ = ConstCacheSize;
	cache_ = new char[ConstCacheSize];
	err_msg_ = new char[ConstCacheSize/4];
	status_ = SSHStatus::STAT_SSH_DISCONNECTED;
}

SSHConnector::~SSHConnector()
{
	sftp_shutdown();
	//
	if (cache_ != nullptr)
	{
		delete[] cache_;
		cache_ = nullptr;
	}
	if (err_msg_ != nullptr)
	{
		delete[] err_msg_;
		err_msg_ = nullptr;
	}
}

int32_t SSHConnector::connect(const char* username, const char* password, const char* host, uint16_t port)
{
	if (status_ == SSHStatus::STAT_SSH_CONNECTED)
	{
		uint32_t hostaddr = inet_addr(host);
		//inet_ntop(AF_INET, &sock_addr_.sin_addr, ip_addr, 32);
		if (hostaddr == sock_addr_.sin_addr.s_addr && port == ntohs(sock_addr_.sin_port))
		{
			return ERR_SSH_SUCCESS;
		}
		else
		{
			disconnect();
		}
	}
	int32_t rc = 0; // 返回结果的临时变量
	//
#ifdef WIN32
	WSADATA wsadata;
	int err;
	err = WSAStartup(MAKEWORD(2, 0), &wsadata);
	if (err != 0) 
	{
		strcpy(err_msg_, "WSAStartup failed with error");
		return ERR_SSH_FAILURE;
	}
#endif
	rc = libssh2_init(0);
	if (rc != 0) 
	{
		strcpy(err_msg_, "libssh2 initialization failed");
		return ERR_SSH_FAILURE;
	}
	/* 连接ssh端口 */
	//inet_pton(AF_INET, host, &sock_addr_.sin_addr);
	socket_ = socket(AF_INET, SOCK_STREAM, 0);
	//
	sock_addr_.sin_family = AF_INET;
	sock_addr_.sin_port = htons(port);
	sock_addr_.sin_addr.s_addr = inet_addr(host);
	if (::connect(socket_, (struct sockaddr*)(&sock_addr_), sizeof(struct sockaddr_in)) != 0) 
	{
		strcpy(err_msg_, "failed to connect!");
		disconnect();
		return ERR_SSH_FAILURE;
	}
	// 建立session
	session_ = libssh2_session_init();
	if (nullptr == session_)
	{
		disconnect();
		return ERR_SSH_FAILURE;
	}

	libssh2_session_set_blocking(session_, 0); // 非阻塞socket

	while ((rc = libssh2_session_startup(session_, socket_)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	if (rc)
	{
		disconnect();
		return ERR_SSH_FAILURE;
	}
	// 检查验证方法 : 仅使用password方式
	char* userauthlist = NULL;
	while ((userauthlist = libssh2_userauth_list(session_, username, strlen(username))) == NULL
		&& libssh2_session_last_error(session_, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	if (NULL == userauthlist || strstr(userauthlist, "password") == NULL)
	{
		disconnect();
		return ERR_SSH_FAILURE;
	}
	// auth
	while ((rc = libssh2_userauth_password(session_, username, password)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	if (rc)
	{
		disconnect();
		return ERR_SSH_FAILURE;
	}
	status_ = SSHStatus::STAT_SSH_CONNECTED;
	//
	return ERR_SSH_SUCCESS;
}

SSHStatus SSHConnector::status() const
{
	return status_;
}

void SSHConnector::disconnect()
{
	status_ = SSHStatus::STAT_SSH_DISCONNECTED;
}

char* SSHConnector::error()
{
	return err_msg_;
}

// ssh
int32_t SSHConnector::exec(const char* commandline, char* out, int32_t* outsize, char* err, int32_t* errsize, int32_t outfd, int32_t errfd)
{
	if (status_ == SSHStatus::STAT_SSH_DISCONNECTED)
	{
		strcpy(err_msg_, "None connection yet");
		return ERR_SSH_REFUSE;
	}
	int32_t rc = 0;
	int32_t ret = 0;
	int32_t _outsize = 0;
	if (outsize != nullptr)
		_outsize = *outsize;
	int32_t _errsize = 0;
	if (errsize != nullptr)
		_errsize = *errsize;
	LIBSSH2_CHANNEL* channel = NULL;
	//
	while ((channel = libssh2_channel_open_session(session_)) == NULL
		&& libssh2_session_last_error(session_, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	if (channel == nullptr)
	{
		strcpy(err_msg_, "Open session failure");
		return ERR_SSH_FAILURE;
	}
	//
	libssh2_channel_set_blocking(channel, 1);
	while ((rc = libssh2_channel_exec(channel, commandline)) == LIBSSH2_ERROR_EAGAIN && wait_for_socket() >= 0);
	if (rc > 0)
	{
		ret = -1;
		goto clearup;
	}
	// 获取标准输出
	if (0 == rc && (outfd >= 0 || (out != nullptr && _outsize > 0)))
	{
		*outsize = 0;
		while (true)
		{
			int32_t count = libssh2_channel_read(channel, cache_, cache_size_);
			if (LIBSSH2_ERROR_EAGAIN == count)
			{
				wait_for_socket();
				continue;
			}
			if (count > 0)
			{
				if (outfd >= 0)
					_write(outfd, cache_, count);
				//
				count = _outsize > count ? count : _outsize;
				if (out != nullptr && count > 0)
				{
					memcpy(out, cache_, count);
					out += count;
					_outsize -= count;
					*out = 0;
					if (outsize != nullptr)
						*outsize += count;
				}
			}
			else
			{
				break;
			}
		}
	}
	// 获取标准错误
	if (0 == rc && (errfd >= 0 || (err != nullptr && _errsize > 0)))
	{
		*errsize = 0;
		while (true)
		{
			int32_t count = libssh2_channel_read(channel, cache_, cache_size_);
			if (LIBSSH2_ERROR_EAGAIN == count)
			{
				wait_for_socket();
				continue;
			}
			if (count > 0)
			{
				if (errfd >= 0)
					_write(errfd, cache_, count);
				//
				count = _errsize > count ? count : _errsize;
				if (err != nullptr && count > 0)
				{
					memcpy(err, cache_, count);
					err += count;
					_errsize -= count;
					*err = 0;
					if (errsize != nullptr)
						*errsize += count;
				}
			}
			else
			{
				break;
			}
		}
	}

clearup:
	while (channel && (rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN && wait_for_socket() >= 0);
	if (channel && rc == 0)
	{
		ret = libssh2_channel_get_exit_status(channel);
		libssh2_channel_free(channel);
		channel = NULL;
	}
	//
	return ERR_SSH_SUCCESS;
}

// sftp
int32_t SSHConnector::sftp_open(const char* path, int32_t flag, int32_t mode)
{
	if (sftp_ == nullptr)
		sftp_init();
	//
	if (sftp_handle_ != nullptr)
		sftp_close();
	//
	while ((sftp_handle_ = libssh2_sftp_open(sftp_, path, flag, mode)) == NULL
		&& libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (sftp_handle_ != nullptr ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

int32_t SSHConnector::sftp_close()
{
	if (NULL == sftp_handle_)
		return 0;
	//
	int rc = 0;
	while ((rc = libssh2_sftp_close(sftp_handle_)) == LIBSSH2_ERROR_EAGAIN);
	//
	sftp_handle_ = nullptr;
	//
	return (rc == 0 ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

int32_t SSHConnector::sftp_read(char* buffer, int32_t size)
{
	int32_t realRead = 0;
	int32_t _size = size;
	while (_size > 0)
	{
		int32_t count = 0;
		while ((count = libssh2_sftp_read(sftp_handle_, buffer, _size)) == LIBSSH2_ERROR_EAGAIN
			&& wait_for_socket() >= 0);
		if (count <= 0)
			break;
		//
		buffer += count;
		_size -= count;
		realRead += count;
	}
	//
	return realRead;
}

int32_t SSHConnector::sftp_write(const char* buffer, int32_t size)
{
	int32_t realWrite = 0;
	int32_t _size = size;
	while (_size > 0)
	{
		int32_t count = 0;
		while ((count = libssh2_sftp_write(sftp_handle_, buffer, _size)) == LIBSSH2_ERROR_EAGAIN
			&& wait_for_socket() >= 0);
		if (count <= 0)
			break;
		//
		buffer += count;
		_size -= count;
		realWrite += count;
	}
	//
	return realWrite;
}

//
int32_t SSHConnector::sftp_open_dir(const char* path)
{
	if (sftp_ == nullptr)
		sftp_init();
	//
	if (sftp_handle_ != nullptr)
		sftp_close();
	//
	while ((sftp_handle_ = libssh2_sftp_opendir(sftp_, path)) == NULL
		&& libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (sftp_handle_ != nullptr ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

int32_t SSHConnector::sftp_close_dir()
{
	return sftp_close();
}

SFTP_FILE_INFO* SSHConnector::sftp_read_dir()
{
	int32_t rc = 0;
	int32_t size = 256;
	char buffer[256] = { 0x00 };
	//
	auto attrs = new LIBSSH2_SFTP_ATTRIBUTES();
	while ((rc = libssh2_sftp_readdir(sftp_handle_, buffer, size, attrs)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	if (rc < 0)
	{
		delete attrs;
		return nullptr;
	}
	auto fileInfo = new SFTP_FILE_INFO();
	fileInfo->flags = attrs->flags;
	fileInfo->filesize = attrs->filesize;
	fileInfo->uid = attrs->uid;
	fileInfo->gid = attrs->gid;
	fileInfo->atime = attrs->atime;
	fileInfo->mtime = attrs->mtime;
	fileInfo->permissions = attrs->permissions;
	memcpy(fileInfo->filename, buffer, rc);
	//
	return fileInfo;
}

int32_t SSHConnector::sftp_unlink(const char* path)
{
	int32_t rc = 0;
	while ((rc = libssh2_sftp_unlink(sftp_, path)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (rc == 0 ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

int32_t SSHConnector::sftp_mkdir(const char* path, int32_t mode)
{
	int32_t rc = 0;
	while ((rc = libssh2_sftp_mkdir(sftp_, path, mode)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (rc == 0 ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

int32_t SSHConnector::sftp_rmdir(const char* path)
{
	int32_t rc = 0;
	while ((rc = libssh2_sftp_rmdir(sftp_, path)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (rc == 0 ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

SFTP_FILE_INFO* SSHConnector::sftp_stat(const char* path)
{
	int32_t rc = 0;
	auto attrs = new LIBSSH2_SFTP_ATTRIBUTES();
	while ((rc = libssh2_sftp_stat(sftp_, path, attrs)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	if (rc < 0)
	{
		delete attrs;
		return nullptr;
	}
	auto fileInfo = new SFTP_FILE_INFO();
	fileInfo->flags = attrs->flags;
	fileInfo->filesize = attrs->filesize;
	fileInfo->uid = attrs->uid;
	fileInfo->gid = attrs->gid;
	fileInfo->atime = attrs->atime;
	fileInfo->mtime = attrs->mtime;
	fileInfo->permissions = attrs->permissions;
	memcpy(fileInfo->filename, path, strlen(path));
	//
	return fileInfo;
}

SFTP_FILE_INFO* SSHConnector::sftp_lstat(const char* path)
{
	int32_t rc = 0;
	auto attrs = new LIBSSH2_SFTP_ATTRIBUTES();
	while ((rc = libssh2_sftp_lstat(sftp_, path, attrs)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	auto fileInfo = new SFTP_FILE_INFO();
	fileInfo->flags = attrs->flags;
	fileInfo->filesize = attrs->filesize;
	fileInfo->uid = attrs->uid;
	fileInfo->gid = attrs->gid;
	fileInfo->atime = attrs->atime;
	fileInfo->mtime = attrs->mtime;
	fileInfo->permissions = attrs->permissions;
	memcpy(fileInfo->filename, path, strlen(path));
	//
	return fileInfo;
}

int32_t SSHConnector::sftp_setstat(const char* path, SFTP_FILE_INFO* attrs)
{
	int32_t rc = 0;
	auto _attrs = new LIBSSH2_SFTP_ATTRIBUTES();
	_attrs->flags = attrs->flags;
	_attrs->filesize = attrs->filesize;
	_attrs->uid = attrs->uid;
	_attrs->gid = attrs->gid;
	_attrs->atime = attrs->atime;
	_attrs->mtime = attrs->mtime;
	_attrs->permissions = attrs->permissions;
	//
	while ((rc = libssh2_sftp_setstat(sftp_, path, _attrs)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (rc == 0 ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

char* SSHConnector::sftp_readlink(const char* path)
{
	int32_t rc = 0;
	int32_t size = 256;
	char* buffer = new char[256];
	memset(buffer, 0x00, 256);
	while ((rc = libssh2_sftp_readlink(sftp_, path, buffer, size)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	// 需要释放
	return buffer;
}

int32_t SSHConnector::sftp_symlink(const char* path, const char* link)
{
	int32_t rc = 0;
	while ((rc = libssh2_sftp_symlink(sftp_, path, (char*)link)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (rc == 0 ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

char* SSHConnector::sftp_realpath(const char* path)
{
	int32_t rc = 0;
	int32_t size = 256;
	char* buffer = new char[256];
	while ((rc = libssh2_sftp_readlink(sftp_, path, buffer, size)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return buffer;
}

// local->remote
int32_t SSHConnector::sftp_copy_file(const char* local, const char* remote)
{
	struct stat st;
	FD_ZERO(&st, sizeof(st));
	stat(local, &st);
	//
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	init_attrs(&attrs, &st);
	int32_t fd = ::_open(local, _O_RDONLY);
	if (fd < 0)
		return ERR_SSH_FAILURE;
	//
	auto res = sftp_open(remote, LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, attrs.permissions & 0777);
	if (res == ERR_SSH_FAILURE)
	{
		::_close(fd);
		return ERR_SSH_FAILURE;
	}
	//
	while (true)
	{
		int32_t rn = 0, wn = 0;
		while ((rn = ::_read(fd, cache_, cache_size_)) == -1 && EAGAIN == errno);
		if (rn > 0)
		{
			wn = sftp_write(cache_, rn);
			if (wn != rn)
			{
				res = ERR_SSH_FAILURE;
				break;
			}
		}
		if (rn <= 0)
		{
			if (rn < 0)
				res = ERR_SSH_FAILURE;
			break;
		}
	};
	//
	::_close(fd);
	sftp_close();
	//
	SFTP_FILE_INFO fileInfo;
	fileInfo.flags = attrs.flags;
	fileInfo.filesize = attrs.filesize;
	fileInfo.uid = attrs.uid;
	fileInfo.gid = attrs.gid;
	fileInfo.atime = attrs.atime;
	fileInfo.mtime = attrs.mtime;
	fileInfo.permissions = attrs.permissions;
	sftp_setstat(remote, &fileInfo);
	//
	return res;
}

int32_t SSHConnector::sftp_copy_link(const char* local, const char* remote)
{
	/*
	if (::readlink(local) < 0)
	{
		return ERR_SSH_FAILURE;
	}
	return sftp_symlink(remote, buf);
	*/
	return ERR_SSH_FAILURE;
}

int32_t SSHConnector::sftp_copy_dir(const char* local, const char* remote)
{
	int32_t ret = 0;
	struct stat st;
	FD_ZERO(&st, sizeof(st));
	stat(local, &st);
	if (!S_ISDIR(st.st_mode))
		return ERR_SSH_FAILURE;
	//
	DIR* dir = ::opendir(local);
	if (NULL == dir)
		return ERR_SSH_FAILURE;
	//
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	init_attrs(&attrs, &st);
	sftp_mkdir(remote, attrs.permissions & 0777);
	auto fileInfo = sftp_stat(remote);
	if (fileInfo == nullptr)
		return ERR_SSH_FAILURE;
	//
	struct dirent entry, * pentry;
	while (readdir_r(dir, &entry, &pentry) == 0)
	{
		if (NULL == pentry)
			break;
		//
		if (strncmp(entry.d_name, ".", 1) == 0 || strncmp(entry.d_name, "..", 2) == 0)
			continue;
		//
		std::string _local = std::string(local) + "/" + std::string(entry.d_name);
		std::string _remote = std::string(remote) + "/" + std::string(entry.d_name);
		sftp_copy(_local.c_str(), _remote.c_str());
	}
	::closedir(dir);
	dir = NULL;
	//
	return ERR_SSH_SUCCESS;
}

int32_t SSHConnector::sftp_copy(const char* local, const char* remote)
{
	std::string _local = AdjustPath(local);
	std::string _remote = AdjustPath(remote);
	//
	struct stat st;
	FD_ZERO(&st, sizeof(st));
	if (::stat(_local.c_str(), &st))
		return -1;
	//
	auto attrs = sftp_lstat(_remote.c_str());
	if (attrs == nullptr)
		return -1;
	//
	if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS && LIBSSH2_SFTP_S_ISDIR(attrs->permissions))
		_remote = _remote + "/" + getBaseName(_local.c_str());
	//
	int32_t res = 0;
	if (S_ISREG(st.st_mode))
		res = sftp_copy_file(_local.c_str(), _remote.c_str());
	else if (S_ISLNK(st.st_mode))
		res = sftp_copy_link(_local.c_str(), _remote.c_str());
	else if (S_ISDIR(st.st_mode))
		res = sftp_copy_dir(_local.c_str(), _remote.c_str());
	else
		res = -1;
	//
	return ERR_SSH_SUCCESS;
}

// other
int32_t SSHConnector::chown(const char* remote, const char* user, const char* group)
{
	// chown root:wheel /tmp/test.txt
	std::string commandline = std::string("chown ") + std::string(user) + ":" + std::string(group) + " " + std::string(remote);
	int32_t res = exec(commandline.c_str());
	if (res != 0)
		return ERR_SSH_FAILURE;
	//
	return ERR_SSH_SUCCESS;
}

int32_t SSHConnector::chmod(const char* remote, int32_t mode)
{
	// chmod 755 /tmp/test.txt
	std::string commandline = std::string("chmod ") + std::to_string(mode) + " " + std::string(remote);
	int32_t res = exec(commandline.c_str());
	if (res != 0)
		return ERR_SSH_FAILURE;
	//
	return ERR_SSH_SUCCESS;
}

int32_t SSHConnector::send_file(const char* local, const char* remote, int32_t keep_owner)
{
	off_t total_send = 0;
	struct stat st;
	if (stat(local, &st))
		return -2;
	//
	int32_t ret = 0;
	int32_t fd = 0;  // local file fd
	LIBSSH2_SFTP* sftp_session = NULL;
	LIBSSH2_SFTP_HANDLE* sftp_handle = NULL;
	while ((sftp_session = libssh2_sftp_init(session_)) == NULL
		&& libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN
		/*&& waitsocket()>=0*/);
	if (NULL == sftp_session)
		return -3;
	//
	while ((sftp_handle = libssh2_sftp_open(sftp_session, remote,
		LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
		st.st_mode)) == NULL
		&& libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN);
	if (NULL == sftp_handle)
	{
		ret = -1;
		goto clearup;
	}
	fd = _open(local, O_RDONLY);
	if (fd < 0)
	{
		ret = -1;
		goto clearup;
	}
	//
	while (true)
	{
		int32_t nread = ::_read(fd, cache_, cache_size_);
		if (nread <= 0)
		{
			if (nread < 0)
			{
				// read出错
			}
			break;
		}
		char* write_ptr = cache_;
		while (nread > 0)
		{
			int32_t nwrite = libssh2_sftp_write(sftp_handle, write_ptr, nread);
			if (LIBSSH2_ERROR_EAGAIN == nwrite)
				continue;
			//
			if (nwrite < 0)
				break;
			else
			{
				total_send += nwrite;
				nread -= nwrite;
				write_ptr += nwrite;
			}
		}
		// 仍有未写入的序列, 则出错推出循环
		if (nread)
			break;
	}
	//
	if (total_send < st.st_size)
		ret = -1;
	//
	if (keep_owner == 1)
		chown(remote, getNameByUid(st.st_uid).c_str(), getNameByGid(st.st_gid).c_str());

clearup:
	if (fd > 0) 
		::_close(fd);
	//
	while (sftp_handle && libssh2_sftp_close(sftp_handle) == LIBSSH2_ERROR_EAGAIN);
	while (sftp_session && libssh2_sftp_shutdown(sftp_session) == LIBSSH2_ERROR_EAGAIN);
	sftp_handle = NULL;
	sftp_session = NULL;
	//
	return ERR_SSH_SUCCESS;
}

int32_t SSHConnector::recv_file(const char* local, const char* remote)
{
	off_t total_recv = 0;
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	struct stat st;
	LIBSSH2_SFTP* sftp_session = NULL;
	LIBSSH2_SFTP_HANDLE* sftp_handle = NULL;
	int rc = 0;
	int fd = 0;
	int ret = 0;
	while ((sftp_session = libssh2_sftp_init(session_)) == NULL
		&& libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN
		/*&& waitsocket()>=0*/);
	if (NULL == sftp_session)
		return -1;
	//
	while ((sftp_handle = libssh2_sftp_open(sftp_session, remote, LIBSSH2_FXF_READ, 0)) == NULL
		&& libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN);
	if (NULL == sftp_handle)
	{
		ret = -1;
		goto clearup;
	}
	while ((rc = libssh2_sftp_stat(sftp_session, remote, &attrs) == LIBSSH2_ERROR_EAGAIN));
	if (rc)
	{
		ret = -1;
		goto clearup;
	}
	else
	{
		// FIX ME : 未检查是否为文件
		st.st_size = attrs.flags & LIBSSH2_SFTP_ATTR_SIZE ? attrs.filesize : 0;
		st.st_mode = attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS ? attrs.permissions : 0644;
		st.st_atime = attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME ? attrs.atime : std::time(NULL);
		st.st_mtime = attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME ? attrs.mtime : std::time(NULL);
		fd = _open(local, O_RDWR | O_CREAT | O_TRUNC, st.st_mode);
	}
	if (fd < 0)
	{
		ret = -1;
		goto clearup;
	}
	//
	while (true)
	{
		int nread = libssh2_sftp_read(sftp_handle, cache_, cache_size_);
		if (LIBSSH2_ERROR_EAGAIN == nread)
		{
			wait_for_socket();
			continue;
		}
		if (nread <= 0)
		{
			if (nread < 0)
			{
				// libssh2_channel_read错误
				ret = -1;
			}
			break;
		}
		char* write_ptr = cache_;
		while (nread > 0)
		{
			int nwrite = ::_write(fd, write_ptr, nread);
			if (nwrite < 0)
			{
				break;
			}
			else
			{
				total_recv += nwrite;
				nread -= nwrite;
				write_ptr += nwrite;
			}
		}
		if (nread)
		{
			ret = -1;
			break;
		}
	}
	if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE && total_recv < (off_t)attrs.filesize)
	{
		ret = -1;
	}
clearup:
	if (fd > 0) 
		::_close(fd);
	//
	while (sftp_handle && libssh2_sftp_close(sftp_handle) == LIBSSH2_ERROR_EAGAIN);
	while (sftp_session && libssh2_sftp_shutdown(sftp_session) == LIBSSH2_ERROR_EAGAIN);
	sftp_handle = NULL;
	sftp_session = NULL;
	//
	return ERR_SSH_SUCCESS;
}

int32_t SSHConnector::wait_for_socket(int32_t second)
{
	struct timeval timeout;
	fd_set fd;
	fd_set* writefd = NULL;
	fd_set* readfd = NULL;
	int dir;
	//
	timeout.tv_sec = (second > 0 ? second : 10);
	timeout.tv_usec = 0;
	//
	FD_ZERO(&fd);
	FD_SET(socket_, &fd);
	/* now make sure we wait in the correct direction */
	dir = libssh2_session_block_directions(session_);

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		readfd = &fd;
	//
	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		writefd = &fd;
	//
	return select(socket_ + 1, readfd, writefd, NULL, &timeout);
}

int32_t SSHConnector::sftp_init()
{
	if (sftp_ == nullptr)
	{
		while ((sftp_ = libssh2_sftp_init(session_)) == NULL
			&& libssh2_session_last_error(session_, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN
			&& wait_for_socket() >= 0);
	}
	//
	return (sftp_ != nullptr ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

int32_t SSHConnector::sftp_shutdown()
{
	if (NULL == sftp_)
		return 0;
	//
	int rc = 0;
	while ((rc = libssh2_sftp_shutdown(sftp_)) == LIBSSH2_ERROR_EAGAIN
		&& wait_for_socket() >= 0);
	//
	return (rc == 0 ? ERR_SSH_SUCCESS : ERR_SSH_FAILURE);
}

void SSHConnector::init_attrs(LIBSSH2_SFTP_ATTRIBUTES* attrs, struct stat* st)
{
	FD_ZERO(attrs, sizeof(*attrs));
	attrs->filesize = st->st_size;
	attrs->uid = 1000;// st->st_uid;
	attrs->gid = 1000;// st->st_gid;
	attrs->flags |= LIBSSH2_SFTP_ATTR_SIZE;
	attrs->permissions = 0755;// st->st_mode;
	attrs->flags |= LIBSSH2_SFTP_ATTR_PERMISSIONS;
	attrs->atime = st->st_atime;
	attrs->mtime = st->st_mtime;
	attrs->flags |= LIBSSH2_SFTP_ATTR_ACMODTIME;
}

std::string SSHConnector::getNameByUid(uid_t uid)
{
	std::string name;

	return name;
}

std::string SSHConnector::getNameByGid(gid_t gid)
{
	std::string name;

	return name;
}

std::string SSHConnector::getBaseName(const char* path)
{
	std::string p = AdjustPath(path);
	std::string::size_type pos = p.rfind('/');
	return p.substr(pos + 1);
}

std::string SSHConnector::getDirName(const char* path)
{
	std::string p = AdjustPath(path);
	std::string::size_type pos = p.rfind('/');
	return p.substr(0, pos);
}

std::string SSHConnector::AdjustPath(const char* path)
{
	std::string p{ path };
	std::string::size_type pos_pre = 0, pos = 0;
	while ((pos = p.find("//", pos_pre)) != std::string::npos)
	{
		p.replace(pos, 2, "/");
		pos_pre = pos;
	}
	pos = p.rfind("/");
	if (pos == p.size() - 1)
	{
		p = p.substr(0, pos);
	}
	//
	return p;
}

