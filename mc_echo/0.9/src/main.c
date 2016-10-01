#include	"server.h"

#if MC_HAVE_SIGSETJMP
sigjmp_buf	mc_env;
#endif
int	mc_listenfd;
volatile int	mc_restart;	

static void	mc_set_startup(void);
static void	mc_check_environment(void);
static void	mc_enlargelimit(int resource);

static void
mc_check_environment(void)
{
	printf("%s ANSI C header files\n", 
#if STDC_HEADERS
	"Support");
#else
	"Don't support");
#endif
	printf("%s POSIX header files\n", 
#if MC_POSIX_HEADERS
	"Support");
#else
	"Don't support");
#endif
	printf("%s restart by SIGHUP\n",	
#if MC_HAVE_SIGSETJMP
	"Support");
#else
	"Don't support");
#endif
	printf("%s chroot function\n",
#if HAVE_CHROOT
	"Support");
#else
	"Don't support");
#endif
	printf("%s setuid/setgid function\n",
#if HAVE_SETUID
	"Support");
#else
	"Don't support");
#endif
#if MC_USE_KQUEUE
	printf("Use freebsd kqueue\n");
#elif MC_USE_EPOLL
	printf("Use linux epoll\n");
#elif MC_USE_DEVPOLL
	printf("Use sunos devpoll\n");
#elif MC_USE_POLL	
	printf("Use poll\n");
#else
	printf("Don't support poll function\n");
#endif
	mc_enlargelimit(RLIMIT_NPROC);
        mc_enlargelimit(RLIMIT_NOFILE);
	printf("Max child processes %ld\n", sysconf(_SC_CHILD_MAX));
	printf("Max file descriptor %ld\n", sysconf(_SC_OPEN_MAX) - MC_FD_PRIVATE); 
	mc_free_startup();
	exit(0);
}

static void
mc_enlargelimit(int resource)
{
#if MC_HAVE_INCREASE_LIMIT
	struct rlimit	limit;

	if(getrlimit(resource, &limit) == 0){
		limit.rlim_cur = limit.rlim_max;
		setrlimit(resource, &limit);
	}
#endif
}

static void
mc_set_startup(void)
{
	int	limit;
	
	if(mc_restart)
		goto out;
	if(mc_startup->s_logfile == NULL){ 
		mc_free_startup();
		mc_err("Error %u: don't provie log file\n", getpid());
	}
	if(mc_startup->s_rootpath == NULL || access(mc_startup->s_rootpath, F_OK) == -1){ 
		mc_free_startup();
		mc_err("Error %u: don't provie rootpath\n", getpid());
	}
out:
	if(!mc_startup->s_port){ 
		mc_free_startup();
		mc_err("Error %u: don't provie port\n", getpid());
	}	
	mc_enlargelimit(RLIMIT_NOFILE);
        if((limit = sysconf(_SC_OPEN_MAX)) == -1){
                mc_free_startup();
                mc_err("Error %u: failed to get maxinum of file descriptor: %s\n", getpid(), strerror(errno));
        }else if(!mc_startup->s_schd.maxfds || mc_startup->s_schd.maxfds > (limit - MC_FD_PRIVATE))
                mc_startup->s_schd.maxfds = limit - MC_FD_PRIVATE;
	if(!mc_startup->s_schd.maxproc || mc_startup->s_schd.maxproc > (limit - MC_FD_PRIVATE))
		mc_startup->s_schd.maxproc = limit - MC_FD_PRIVATE; 
	if(!mc_startup->s_cycle) 
		mc_startup->s_cycle = 1;
	if(!mc_startup->s_schd.procs)	
		mc_startup->s_schd.procs = 1;	
	if(!mc_startup->s_backlog)
		mc_startup->s_backlog = 1024;
	if(!mc_startup->s_schd.thresholdfds_u) 
		mc_startup->s_schd.thresholdfds_u = (limit = mc_startup->s_schd.maxfds / 2) ? limit : 1;
	if(!mc_startup->s_schd.thresholdfds_l) 
		mc_startup->s_schd.thresholdfds_l = (limit = mc_startup->s_schd.maxfds / 5) ? limit : 1;
	if(mc_init_mem() == -1){
		mc_free_startup();
		mc_err("Error %u: failed to init shared memory\n", getpid());
	}
	mc_daemon();
}

int
main(int argc, char *argv[])
{
	char	*p;
	int	fd;
	socklen_t       addrlen;
        struct sockaddr_storage addr;

#if HAVE_SETLOCALE 
	setlocale(LC_TIME, "C");
#endif
#ifndef MC_HAVE_SIGSETJMP
	mc_err("Error %u: don't support restart by SIGHUP\n", getpid);
#endif
	if(sigsetjmp(mc_env, 1) == 1)
		mc_free_startup();
	if((mc_startup = mc_deal_configuration(argc, argv)) != NULL){ 
		if(mc_startup->s_version)
			mc_show_version();
		if(mc_startup->s_check)
			mc_check_environment();
		mc_set_startup(); 
		if((mc_listenfd = mc_get_sockfd(mc_startup->s_domain, SOCK_STREAM, 0)) == -1){
                	mc_free_startup();
                	mc_err("Error %u: failed to get socket file descriptor for listening: %s\n", getpid(), strerror(errno));
        	}
		for( ; ; ){ /* 无限循环，父进程不断的接受请求 */
			addrlen = sizeof(addr);
			if((fd = mc_accept(mc_listenfd, MC_SA(&addr), &addrlen)) > 0 && mc_send_fd(fd) == -1){ 
				mc_warn("Error %u: failed to deal request from %s\n", getpid(), p = mc_print_ip(MC_SA(&addr)));
				free(p);
			}
			if(fd > 0) /* 父进程不处理请求 */
				mc_close(fd);
		}
	}else
		mc_err("Error %u: failed to deal configuration parameters\n", getpid());
	return 0;
}
