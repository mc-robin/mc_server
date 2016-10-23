#include	"event.h"
#include	"server.h"

SSL	**mc_ssl;
int	mc_schdid;	
int	mc_recvfd;	
mc_event	mc_evp;	
mc_childproc   	mc_request_info; 

static int
mc_add_request(void)
{
	char	buf[1];
	int	fd, procs;
	struct msghdr	msg;
	struct cmsghdr 	*ptr;
	struct iovec	iov[1];
	char	control[CMSG_SPACE(sizeof(int))];

	iov[0].iov_len = 1;
	iov[0].iov_base = buf;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = control;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	if(mc_recvmsg(mc_recvfd, &msg, 0) <= 0)
		return -1;
	if((ptr = CMSG_FIRSTHDR(&msg)) != NULL && ptr->cmsg_len == CMSG_LEN(sizeof(int))){
		if(ptr->cmsg_level != SOL_SOCKET || ptr->cmsg_type != SCM_RIGHTS)
			return -1;
		fd = *((int *)CMSG_DATA(ptr));
	}else
		return -1;
	if(mc_startup->s_usessl){
		if((mc_ssl[fd] = SSL_new(mc_ctx)) == NULL || SSL_set_fd(mc_ssl[fd], fd) != 1 || SSL_accept(mc_ssl[fd]) != 1){
			if(mc_ssl[fd]){
				SSL_free(mc_ssl[fd]);
				mc_ssl[fd] = NULL;	
			}
			return -1;
		}
	}
	if(mc_evp->add(mc_evp, fd, MC_EVENT_IN) == -1){
		mc_close(fd);
		return -1;
	}
#if 0 
	mc_warn("Debug %u: recv %d\n", getpid(), fd);
#endif
	mc_lock();	
	mc_request_info->c_cnt++;
	mc_unlock();
	return 0;
}

static int
mc_del_request(int fd)
{
	int	procs;

	if(mc_evp->del(mc_evp, fd, MC_EVENT_IN) == -1) 
		return -1;
	mc_lock();
	if(mc_startup->s_usessl){
		shutdown(fd, 1);
		SSL_shutdown(mc_ssl[fd]);
		mc_close(fd);	
		SSL_free(mc_ssl[fd]);
		mc_ssl[fd] = NULL;
	}else
		mc_close(fd);
	mc_request_info->c_cnt--;
#if 0 
	mc_warn("Debug %u: delete %d\n", getpid(), fd);
#endif
	if(mc_request_info->c_cnt == 0 && mc_request_info->c_fd < 0){ 
		mc_unlock();
		exit(0);
	}
	mc_unlock();
	return 0;
}

static int 
mc_deal_request(const mc_pollfd pfp)
{
	int	n;
	char	buf[BUFSIZ];

#if 0 
	mc_warn("Debug %u: deal %d , revents = %d: recvfd = %d\n", getpid(), pfp->fd, pfp->revents, mc_recvfd);
#endif
	switch(pfp->revents){
	case MC_EVENT_IN:
		if(pfp->fd == mc_recvfd)
			return mc_add_request();
		if((n = mc_read(pfp->fd, buf, BUFSIZ)) > 0){
			mc_write(pfp->fd, buf, n);
		}else 
			return mc_del_request(pfp->fd); 
		break;
	case MC_EVENT_OUT:
		break;
	case MC_EVENT_ERR:
		return mc_del_request(pfp->fd);
	}
	return 0;
}

static void
mc_deal_client(mc_childproc chp)
{
        int     i, n;
	struct mc_pollfd	pollfd;

	mc_request_info = chp;
	for(i = mc_listenfd; i < mc_startup->s_configinfo.c_schd.s_maxfds; i++){ /* mc_listenfd == 4 */
		if(i != mc_recvfd)
			mc_close(i);
	}
        if(mc_init_sig(1) == -1) 
                mc_err("Error %s:%d %u: failed to init singal for treatment process\n", __FILE__, __LINE__, getpid());
        if((mc_evp = mc_init_event(mc_startup->s_configinfo.c_schd.s_maxfds)) == NULL)
                mc_err("Error %s:%d %u: failed to init event system\n", __FILE__, __LINE__, getpid());
        if(mc_evp->add(mc_evp, mc_recvfd, MC_EVENT_IN) == -1)
                mc_err("Error %s:%d %u: failed to add listen file descriptor to event system\n", __FILE__, __LINE__, getpid());
	if(mc_startup->s_usessl && (mc_ssl = calloc(mc_startup->s_configinfo.c_schd.s_maxfds, sizeof(struct SSL *))) == NULL)
		mc_err("Error %s:%d %u: out of memory\n", __FILE__, __LINE__, getpid());
        for( ; ; ){
                if((n = mc_evp->poll(mc_evp, -1)) <= 0)
                        continue;
                for(i = 0; i < n; i++){ 
                        if(mc_evp->traverse(mc_evp, &pollfd) == 0)
                                mc_deal_request(&pollfd);        
                }
        }
}

char	*
mc_print_ip(struct sockaddr *addr)
{
	char	ipbuf[INET6_ADDRSTRLEN];

	switch(addr->sa_family){
	case AF_INET:
		return mc_strdup(inet_ntop(AF_INET, &(MC_SA4(addr)->sin_addr), ipbuf, sizeof(ipbuf))); 
	case AF_INET6:
		return mc_strdup(inet_ntop(AF_INET6, &(MC_SA6(addr)->sin6_addr), ipbuf, sizeof(ipbuf)));
	default:
		return mc_strdup("unknow");
	}
}

int
mc_schedule(void)
{
        int     i, cnt, procs;

        mc_init_sig(-1);
        alarm(mc_startup->s_configinfo.c_cycle);
        for( ; ; ){
                pause();
                alarm(mc_startup->s_configinfo.c_cycle);
                mc_lock();
                cnt = procs = 0;
                for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs; i++){
                        if(mc_startup->s_childprocs[i].c_fd > 0){
                                procs++;
                                cnt += mc_startup->s_childprocs[i].c_cnt;
                        }
                }
                if((cnt / procs) > mc_startup->s_configinfo.c_schd.s_thresholdfds_u){
                        for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs && mc_startup->s_childprocs[i].c_fd >= 0; i++)
                                ;
                        if(i != mc_startup->s_configinfo.c_schd.s_maxprocs){
                                mc_startup->s_childprocs[i].c_fd *= -1;
                        }else
                                *mc_startup->s_newproc = 1;
                        mc_unlock();
                        continue;
                }
                if(procs <= mc_startup->s_configinfo.c_schd.s_medianprocs){
                        mc_unlock();
                        continue;
                }
                for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs && mc_startup->s_childprocs[i].c_fd <= 0; i++)
                        ;
                if(i != mc_startup->s_configinfo.c_schd.s_maxprocs)
                        mc_startup->s_childprocs[i].c_fd *= -1;
                mc_unlock();
        }
}

void
mc_daemon(void)
{
	int	i;
	int	fd;
	pid_t	pid;
	char	buf[BUFSIZ];
	struct flock	flock;

	umask(0);
	if((pid = fork()) == -1){
		mc_free_startup();
        	mc_err("Error %s:%d %u: failed to creat a child process: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
	}else if(pid > 0)
		exit(0);	
	if(setsid() == -1){
		mc_free_startup();
        	mc_err("Error %s:%d %u: failed to creat a new session: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
	}
	if(close(STDOUT_FILENO) == -1){
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to close STDOUT_FILENO: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
	}
	if((fd = open(mc_startup->s_configinfo.c_pidfile, O_RDWR | O_CREAT | O_TRUNC, MC_FILE_MODE)) == -1){ /* fd = STDOUT_FILENO */
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to open pid file: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
	}
	mc_memset(&flock, 0, sizeof(flock));
	flock.l_type = F_WRLCK;
	flock.l_whence = SEEK_SET;
	if(fcntl(fd, F_SETLK, &flock) == -1){ /* 防止存在多个程序副本运行 */
		mc_free_startup();
		mc_err("Error %s:%d %u: server is already running\n", __FILE__, __LINE__, getpid()); 
	}
#if HAVE_SNPRINTF
        snprintf(buf, BUFSIZ, "%u\n", getpid());
#else
        sprintf(buf, "%u\n", getpid());
#endif
	i = strlen(buf);
	if(write(fd, buf, i) != i){ /* 写入pid到pid文件 */
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to write pid to pidfile: %s\n", __FILE__, __LINE__, getpid(), strerror(errno)); 
	}
	for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxfds; i++) /* 关闭所有的文件描述符 */
		if(i != STDOUT_FILENO)
                	close(i);
	if((fd = open("/dev/null", O_RDONLY)) == -1 || !(mc_stdin = fdopen(fd, "r"))){
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to redirect stdin\n", __FILE__, __LINE__, getpid()); 
	}
	if((fd = open(mc_startup->s_configinfo.c_logfile, O_WRONLY | O_CREAT, MC_FILE_MODE)) == -1 || !(mc_stderr = fdopen(fd, "a"))){
                mc_free_startup();
                mc_err("Error %s:%d %u: failed to open log file\n", __FILE__, __LINE__, getpid()); 
        }
	mc_stdout = mc_stderr;
	setvbuf(mc_stdin, NULL, _IONBF, 0);
	setvbuf(mc_stderr, NULL, _IONBF, 0);
#if 0
#if HAVE_CHROOT
	if(chroot(mc_startup->s_rootpath) == -1){ 
		mc_free_startup();
		mc_err("Error %u: failed to chroot: %s\n", getpid(), strerror(errno));
	}
#endif
#endif
	if(chdir("/") == -1){
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to switch to rootpath: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
	}
#if HAVE_SETUID	
	if(setgid(mc_startup->s_configinfo.c_gid) || setuid(mc_startup->s_configinfo.c_uid)){ 
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to setgid or setuid: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
	}
#else
	mc_free_startup();
	mc_err("Error %s:%d %u: cannot find setuid and setgid function\n", __FILE__, __LINE__, getpid());
#endif
	if(mc_init_sig(0) == -1){
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to init signal for main process\n", __FILE__, __LINE__, getpid());
	}
	switch((mc_schdid = fork())){
	case -1:
		mc_free_startup();
		mc_err("Error %s:%d %u: failed to create schedule process\n", __FILE__, __LINE__, getpid());
	case 0: 
		mc_close(mc_listenfd);
		mc_schedule();
		break;
	default:
		break;
	}	
}

int
mc_send_fd(int fd)
{
	char	buf[1];
	int	i, n, m;
	struct iovec iov[1];
	struct msghdr   msg;
	struct cmsghdr	*ptr;
	char	control[CMSG_SPACE(sizeof(int))];

	if(*mc_startup->s_newproc)
		mc_creat_child();
	m = -1; 
	mc_lock();
	n = mc_startup->s_configinfo.c_schd.s_maxfds;
	for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs; i++){ 
		if(mc_startup->s_childprocs[i].c_fd > 0 && mc_startup->s_childprocs[i].c_cnt < n){
			m = i;
			n = mc_startup->s_childprocs[i].c_cnt;
		}
	}	
	if(m == -1){
		n = mc_startup->s_configinfo.c_schd.s_maxfds;
                for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs; i++){
                        if(mc_startup->s_childprocs[i].c_fd < 0 && mc_startup->s_childprocs[i].c_cnt < n){
                                m = i;
                                n = mc_startup->s_childprocs[i].c_cnt;
                        }
                }
                mc_unlock();
                if(m == -1){
                        if((m = mc_creat_child()) == -1)
                                return -1;
                }else
                        mc_startup->s_childprocs[i].c_fd *= -1; /* 将闲置进程置为工作状态 */
	}else
		mc_unlock();
	msg.msg_control = control;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	iov[0].iov_len = 1;
	iov[0].iov_base = buf;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	ptr = CMSG_FIRSTHDR(&msg);
	ptr->cmsg_len = CMSG_LEN(sizeof(int));
	ptr->cmsg_level = SOL_SOCKET;
	ptr->cmsg_type = SCM_RIGHTS;
	*((int *)CMSG_DATA(ptr)) = fd;
#if 0 
	mc_warn("Debug %u: send fd %d to process %u\n", getpid(), fd, mc_startup->s_childprocs[m].c_pid);
#endif
	return mc_sendmsg(mc_startup->s_childprocs[m].c_fd, &msg, 0); 
}

int
mc_creat_child(void)
{
	pid_t	pid;
	int	i, fds[2];

	mc_lock();
	for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs && mc_startup->s_childprocs[i].c_fd; i++)
		; 
	if(i == mc_startup->s_configinfo.c_schd.s_maxprocs){
		mc_unlock();
                mc_warn("Error %s:%d %u: failed to creat a child process\n", __FILE__, __LINE__, getpid());
		return -1;
	}
	if(socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) == -1){
		mc_unlock();
		mc_warn("Error %s:%d %u: failed to creat a child process\n", __FILE__, __LINE__, getpid());
		return -1;
	}
	switch((pid = fork())){
	case -1:
		mc_unlock();
		mc_close(fds[0]);
		mc_close(fds[1]);
		mc_warn("Error %s:%d %u: failed to creat a child process: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	case 0: 
		mc_close(fds[0]);
		mc_close(mc_listenfd);
		mc_recvfd = fds[1]; 
		mc_deal_client(&mc_startup->s_childprocs[i]);
	default: 
		mc_close(fds[1]);
		*mc_startup->s_newproc = 0;
		mc_startup->s_childprocs[i].c_cnt = 0;
		mc_startup->s_childprocs[i].c_pid = pid;
		mc_startup->s_childprocs[i].c_fd = fds[0];
		mc_unlock();
		return i;	
	}	
	return 0;
}

int
mc_init_mem(void)
{
	void	*p;
	int	fd, len;
	pthread_mutexattr_t mattr;

	if((p = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED){
                if((fd = open("/dev/zero", O_RDWR)) == -1)
                        return -1;
                if((p = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
                        close(fd);
                        return -1;
                }
                close(fd);
        }
	*(mc_startup->s_newproc = p) = 0; 
	if((p = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED){
		if((fd = open("/dev/zero", O_RDWR)) == -1){
			munmap(mc_startup->s_newproc, sizeof(int));
			return -1;
		}
		if((p = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
			close(fd);
			munmap(mc_startup->s_newproc, sizeof(int));
			return -1;
		}
		close(fd);
	}
	if(sem_init(p, 1, 1) == -1){
		munmap(mc_startup->s_newproc, sizeof(int));
		munmap(p, sizeof(sem_t));
		return -1;
	}
	mc_startup->s_lock.l_pid = 0; 
	mc_startup->s_lock.l_key = p; 
	len = mc_startup->s_configinfo.c_schd.s_maxprocs * MC_CHILDPROC_SIZE;
	if((p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED){ 
		if((fd = open("/dev/zero", O_RDWR)) == -1){
			munmap(mc_startup->s_newproc, sizeof(int));
			munmap(mc_startup->s_lock.l_key, sizeof(pthread_mutex_t)); 	
			return -1;
		}
		if((p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
			close(fd);
			munmap(mc_startup->s_newproc, sizeof(int));
			munmap(mc_startup->s_lock.l_key, sizeof(pthread_mutex_t)); 	
			return -1;
		}	
		close(fd);
	} 
	mc_memset((mc_startup->s_childprocs = p), 0, len);
	return 0;
}

int
mc_get_sockfd(int domain, int type, int protocol)
{
	int	fd;
	int	err;
	int	optval;
	char	port[BUFSIZ];
	struct addrinfo	*res, *head, hints;

	mc_memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = domain;
	hints.ai_socktype = type;		
	hints.ai_protocol = protocol;	
#if HAVE_SNPRINTF
	snprintf(port, BUFSIZ, "%u", mc_startup->s_configinfo.c_port);
#else
	sprintf(port, "%u", mc_startup->s_configinfo.c_port);
#endif
	if((err = getaddrinfo(NULL, port, &hints, &res)) != 0){
		mc_warn("Error %s:%d %u: cannot getaddrinfo: %s\n", __FILE__, __LINE__, getpid(), gai_strerror(err));
		return -1;
	}else{
		head = res;
		optval = 1;
		while(res){
			if((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) >= 0  
				 && !setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) 
				&& !bind(fd, res->ai_addr, res->ai_addrlen) && !listen(fd, mc_startup->s_configinfo.c_backlog)){
				freeaddrinfo(head);
				return fd;
			}
			if(fd >= 0)
				close(fd);
			res = res->ai_next;
		}
	}
	return -1; 						
}
