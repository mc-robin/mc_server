#include	"server.h"

static void
mc_do_restart(int signum)
{
	mc_restart = 1; 	
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
		if(mc_startup->s_lock.l_pid == pid) 
			mc_unlock();
		if(mc_startup->s_lock.l_pid == getpid()){ 
			s = 1;
		}else	
                	mc_lock();
		for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs && mc_startup->s_childprocs[i].c_pid != pid; i++)
			;
		if(i != mc_startup->s_configinfo.c_schd.s_maxprocs){ 
			if((i = mc_startup->s_childprocs[i].c_fd) > 0){
				mc_close(i);
			}else if(i < 0)
				mc_close(i * -1);
			mc_startup->s_childprocs[i].c_fd = 0;
			mc_startup->s_childprocs[i].c_cnt = 0;
			mc_startup->s_childprocs[i].c_pid = 0;
		}
		if(!s)
			mc_unlock();
	}
}

static void
mc_killchildren(int signum)
{
	mc_quit = 1;
}

static void
mc_killself(int signum)
{
	if(mc_startup->s_lock.l_pid == getpid()) 
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

pid_t
mc_wait(int *status)
{
	pid_t	pid;

retry:
	if((pid = wait(status)) == -1 && errno == EINTR)
		goto retry;
	return pid;
}

ssize_t 
mc_read(int fd, void *buf, size_t count)
{
	ssize_t	n;

	if(mc_startup->s_usessl)
		return SSL_read(mc_ssl[fd], buf, count);
retry:
	if((n = read(fd, buf, count)) == -1 && errno == EINTR)
		goto retry;
	return n;
}

ssize_t 
mc_write(int fd, const void *buf, size_t count)
{
	ssize_t	n;

	if(mc_startup->s_usessl)
		return SSL_write(mc_ssl[fd], buf, count);
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
		mc_warn("Error %s:%d %u: failed to ignore signal SIGABRT: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(SIGIO != SIGPOLL && sigaction(SIGIO, &act, NULL)){ 
		mc_warn("Error %s:%d %u: failed to ignore signal SIGIO: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	
	if(sigaction(SIGPOLL, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGPOLL: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTTOU, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGTTOU: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTTIN, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGTTIN: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTSTP, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGTSTP: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGQUIT, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGQUIT: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGPIPE, &act, NULL)){ 
		mc_warn("Error %s:%d %u: failed to ignore signal SIGPIPE: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGTERM, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGTERM: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGUSR1, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGUSR1: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}
	if(sigaction(SIGUSR2, &act, NULL)){
		mc_warn("Error %s:%d %u: failed to ignore signal SIGUSR2: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
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
		mc_warn("Error %s:%d %u: failed to set function to deal signal SIGALRM: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
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
		mc_warn("Error %s:%d %u: failed to set function to deal signal SIGHUP: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
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
		mc_warn("Error %s:%d %u: failed to set function to deal signal SIGINT: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
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
		mc_warn("Error %s:%d %u: failed to set function to deal signal SIGCHLD: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return -1;
	}	
	return 0;
}
