#include	"server.h"

static void
mc_do_restart(int signum)
{
	int	i;

	if(mc_restart)
		return;
	mc_restart = 1; 	
	for(i = 0; i < mc_startup->s_schd.maxproc; i++){ 
		if(mc_startup->s_children[i].pid > 0) 
			kill(mc_startup->s_children[i].pid, SIGINT);
	}
	kill(mc_schdid, SIGINT);
	while(mc_wait(NULL) > 0) 
		;
	siglongjmp(mc_env, 1);
}

static void
mc_alarm(int signum)
{
	return;
}

static void
mc_deal_child(int signum)
{
	pid_t	pid;
	int	i, s;
	
	while((pid = waitpid(-1, NULL, WNOHANG)) > 0){ 
		s = 0;
		if(mc_startup->s_lock.pid == pid) 
			mc_unlock();
		if(mc_startup->s_lock.pid == getpid()){ 
			s = 1;
		}else	
                	mc_lock();
		for(i = 0; i < mc_startup->s_schd.maxproc && mc_startup->s_children[i].pid != pid; i++)
			;
		if(i != mc_startup->s_schd.maxproc){ 
			if((i = mc_startup->s_children[i].fd) > 0){
				mc_close(i);
			}else if(i < 0)
				mc_close(i * -1);
			mc_startup->s_children[i].fd = 0;
			mc_startup->s_children[i].cnt = 0;
			mc_startup->s_children[i].pid = 0;
		}
		if(!s)
			mc_unlock();
	}
}

static void
mc_killchildren(int signum)
{
	int	i;

	if(mc_restart) 
		return;
	for(i = 0; i < mc_startup->s_schd.maxproc; i++){
		if(mc_startup->s_children[i].pid > 0)
			kill(mc_startup->s_children[i].pid, SIGINT);
	}
	kill(mc_schdid, SIGINT);
	while(mc_wait(NULL) > 0) 
		;
	mc_free_startup();
	exit(0);
}

static void
mc_killself(int signum)
{
	if(mc_startup->s_lock.pid == getpid()) 
        	mc_unlock();
	exit(0);
}

int
mc_close(int fd)
{
	int	rtv;

retry:
	if((rtv = close(fd)) == -1 && errno == EINTR)
		goto retry;
	return rtv;
}

struct passwd	*
mc_getpwnam(const char *name)
{
	struct passwd	*up;

retry:
	if((up = getpwnam(name)) == NULL && errno == EINTR)
		goto retry;
	return up;
}

struct passwd	*
mc_getpwuid(uid_t uid)
{
	struct passwd	*up;

retry:
	if((up = getpwuid(uid)) == NULL && errno == EINTR)
		goto retry;
	return up;
}

struct group	*
mc_getgrnam(const char *name)
{
	struct group	*gp;

retry:
	if((gp = getgrnam(name)) == NULL && errno == EINTR)
		goto retry;
	return gp;
}

struct group	*
mc_getgrgid(gid_t gid)
{
	struct group	*gp;

retry:
	if((gp = getgrgid(gid)) == NULL && errno == EINTR)
		goto retry;
	return gp;
}

FILE	*
mc_fopen(const char *path, const char *mode)
{
	FILE	*fp;

retry:
	if((fp = fopen(path, mode)) == NULL && errno == EINTR)
		goto retry;
	return fp;
}

pid_t
mc_wait(int *status)
{
	pid_t	pid;

retry:
	if((pid = wait(status)) == -1 && errno == EINTR)
		goto retry;
	return pid;
}

int
mc_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int	fd;

retry:
	if((fd = accept(sockfd, addr, addrlen)) == -1 && errno == EINTR)
		goto retry;
	return fd;
}

ssize_t 
mc_read(int fd, void *buf, size_t count)
{
	ssize_t	n;

retry:
	if((n = read(fd, buf, count)) == -1 && errno == EINTR)
		goto retry;
	return n;
}

ssize_t 
mc_write(int fd, const void *buf, size_t count)
{
	ssize_t	n;

retry:
	if((n = write(fd, buf, count)) == -1 && errno == EINTR)
		goto retry;
	return n;

}

ssize_t 
mc_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	ssize_t	n;

retry:
	if((n = recvmsg(sockfd, msg, flags)) == -1 && errno == EINTR)
		goto retry;
	return n;
}

ssize_t 
mc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	ssize_t	n;

retry:
	if((n = sendmsg(sockfd, msg, flags)) == -1 && errno == EINTR)
		goto retry;
	return n;
}

/*
 * type:
 *	0父进程
 *	1处理进程
 *	-1调度进程
 */
int
mc_init_sig(int type)
{
	struct sigaction	act;
		
	mc_memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask); 
	act.sa_flags = 0;				
#ifdef SA_INTERRUPT	
	act.sa_flags = SA_INTERRUPT;
#endif
	if(sigaction(SIGABRT, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGABRT: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(SIGIO != SIGPOLL && sigaction(SIGIO, &act, NULL)){ 
		mc_warn("Error %u: failed to ignore signal SIGIO: %s\n", getpid(), strerror(errno));
		return -1;
	}
	
	if(sigaction(SIGPOLL, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGPOLL: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTTOU, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGTTOU: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTTIN, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGTTIN: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTSTP, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGTSTP: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGQUIT, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGQUIT: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGPIPE, &act, NULL)){ 
		mc_warn("Error %u: failed to ignore signal SIGPIPE: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTERM, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGTERM: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGUSR1, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGUSR1: %s\n", getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGUSR2, &act, NULL)){
		mc_warn("Error %u: failed to ignore signal SIGUSR2: %s\n", getpid(), strerror(errno));
		return -1;
	}
	switch(type){
	case -1: 
		act.sa_handler = mc_alarm;
		break;
	default:
		act.sa_handler = SIG_IGN;
		break;
	}
	if(sigaction(SIGALRM, &act, NULL)){
		mc_warn("Error %u: failed to set function to deal  signal SIGALRM: %s\n", getpid(), strerror(errno));
		return -1;
	}
	switch(type){
	case 0: 
		sigemptyset(&act.sa_mask); 
		sigaddset(&act.sa_mask, SIGINT); 
		act.sa_handler = mc_do_restart;
		break;
	default:
		act.sa_handler = SIG_IGN; 
		break;
	}
	if(sigaction(SIGHUP, &act, NULL)){
		mc_warn("Error %u: failed to set function to deal signal SIGHUP: %s\n", getpid(), strerror(errno));
		return -1;
	}
	switch(type){
	case 0: 
		sigemptyset(&act.sa_mask);
		sigaddset(&act.sa_mask, SIGHUP);
		act.sa_handler = mc_killchildren;
		break;
	default:
		sigemptyset(&act.sa_mask);
		act.sa_handler = mc_killself;
		break;
	}
	if(sigaction(SIGINT, &act, NULL)){
		mc_warn("Error %u: cannot set function to deal signal SIGINT: %s\n", getpid(), strerror(errno));
		return -1;
	}
	switch(type){
	case 0: 
		sigemptyset(&act.sa_mask);
                sigaddset(&act.sa_mask, SIGINT);
                sigaddset(&act.sa_mask, SIGHUP);
		act.sa_handler = mc_deal_child;
		break;
	default:
		act.sa_handler = SIG_IGN;
		break;
	}
	if(sigaction(SIGCHLD, &act, NULL)){
		mc_warn("Error %u: failed to set function to deal signal SIGCHLD: %s\n", getpid(), strerror(errno));
		return -1;
	}	
	return 0;
}
