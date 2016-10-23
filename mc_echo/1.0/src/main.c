#include	"event.h"
#include	"server.h"

SSL_CTX	*mc_ctx;
int	mc_quit;
int	mc_restart;
int	mc_listenfd;

static void	mc_reset(void);
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
	struct mc_configinfo *configp;
	
	configp = &mc_startup->s_configinfo;
	if(!configp->c_uid || !configp->c_gid){
		mc_free_startup();
		mc_err("Error %s:%d %u: please provide user and group information\n", __FILE__, __LINE__, getpid());
	}
	if(!configp->c_logfile && (configp->c_logfile = mc_strdup(MC_LOG_FILE)) == NULL){ 
		mc_free_startup();
		mc_err("Error %s:%d %u: please provide log file\n", __FILE__, __LINE__, getpid());
	}
	if(configp->c_logfile[0] != '/'){
		mc_warn("Error %s:%d %u: '%s': not absolute path\n", __FILE__, __LINE__, getpid(), configp->c_logfile);
		mc_free_startup();
		exit(1);
	}
	if(!configp->c_pidfile && (configp->c_pidfile = mc_strdup(MC_PID_FILE)) == NULL){
		mc_free_startup();
		mc_err("Error %s:%d %u: please provide pid file\n", __FILE__, __LINE__, getpid());
	}
	if(configp->c_pidfile[0] != '/'){
		mc_warn("Error %s:%d %u: '%s': not absolute path\n", __FILE__, __LINE__, getpid(), configp->c_pidfile);
		mc_free_startup();
		exit(1);
	}
	if(configp->c_certfile && configp->c_keyfile){
		if(configp->c_certfile[0] != '/' || configp->c_keyfile[0] != '/'){
			mc_warn("Error %s:%d %u: '%s' or '%s' not absolute path\n", __FILE__, __LINE__, getpid(), configp->c_certfile, configp->c_keyfile);
			mc_free_startup();
			exit(1);
		}
		mc_startup->s_usessl = 1;
	}
	if(!configp->c_port){ 
		mc_free_startup();
		mc_err("Error %s:%d %u: please provide port\n", __FILE__, __LINE__, getpid());
	}	
	if(!configp->c_backlog)
		configp->c_backlog = 1024;
	if(!configp->c_cycle)
		configp->c_cycle = 60;	/* 默认调度周期一分钟 */
	mc_enlargelimit(RLIMIT_NOFILE);
        if((limit = sysconf(_SC_OPEN_MAX)) == -1){
                mc_free_startup();
                mc_err("Error %s:%d %u: failed to get maxinum of file descriptor: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
        }else if(!configp->c_schd.s_maxfds || configp->c_schd.s_maxfds > (limit - MC_FD_PRIVATE))
		configp->c_schd.s_maxfds = limit - MC_FD_PRIVATE;
	if(!configp->c_schd.s_maxprocs || configp->c_schd.s_maxprocs > (limit - MC_FD_PRIVATE))
		configp->c_schd.s_maxprocs = limit - MC_FD_PRIVATE;
	if(!configp->c_schd.s_medianprocs)
		configp->c_schd.s_medianprocs = 1; /* 默认处理进程一个 */
	if(configp->c_schd.s_thresholdfds_u < 10)
		configp->c_schd.s_thresholdfds_u = 10; /* 上限最少是10 */
	if(configp->c_schd.s_thresholdfds_l < 1)
		configp->c_schd.s_thresholdfds_l = 1; /* 下限最少是1 */
}

static void
mc_reset(void)
{
	void	*p;
	int	i, fd;

        if(mc_startup->s_configinfo.c_logfile)
                free(mc_startup->s_configinfo.c_logfile);
        if(mc_startup->s_configinfo.c_pidfile)
                free(mc_startup->s_configinfo.c_pidfile);
	mc_startup->s_configinfo.c_uid = mc_startup->s_configinfo.c_gid = 0;
        mc_startup->s_configinfo.c_logfile = mc_startup->s_configinfo.c_pidfile = NULL;
	mc_startup->s_configinfo.c_port = mc_startup->s_configinfo.c_backlog = mc_startup->s_configinfo.c_cycle = 0;
        if(mc_startup->s_childprocs)
                munmap(mc_startup->s_childprocs, mc_startup->s_configinfo.c_schd.s_maxprocs * MC_CHILDPROC_SIZE);
        mc_startup->s_childprocs = NULL;
	mc_memset(&mc_startup->s_configinfo.c_schd, 0, MC_SCHEDINFO_SIZE);
	if(mc_startup->s_usessl){
		free(mc_startup->s_configinfo.c_keyfile);
		free(mc_startup->s_configinfo.c_certfile);
		if(mc_startup->s_configinfo.c_cipher){
			free(mc_startup->s_configinfo.c_cipher);
			mc_startup->s_configinfo.c_cipher = NULL;
		}
		mc_startup->s_configinfo.c_keyfile = mc_startup->s_configinfo.c_certfile = NULL;
                SSL_CTX_free(mc_ctx);
		mc_ctx = NULL;
		mc_startup->s_usessl = 0;
	}
        if((yyin = fopen(mc_startup->s_configfile, "r")) == NULL){
                mc_warn("Error %s:%d %u: failed to open configure file '%s': %s\n", __FILE__, __LINE__, getpid(),
                        mc_startup->s_configfile, strerror(errno));
		mc_free_startup();
		exit(1);
        }
        yyparse();
        fclose(yyin);
        mc_set_startup();
	if(mc_startup->s_usessl){
       		if((mc_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL){
                	mc_free_startup();
                        mc_err("Error %s:%d %u: failed to ssl_ctx_new\n", __FILE__, __LINE__, getpid());
               	}
		SSL_CTX_set_options(mc_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
               	if(SSL_CTX_use_certificate_chain_file(mc_ctx, mc_startup->s_configinfo.c_certfile) != 1 || /* 公钥 */
                	SSL_CTX_use_PrivateKey_file(mc_ctx, mc_startup->s_configinfo.c_keyfile, SSL_FILETYPE_PEM) != 1 ||  /* 私钥 */
                        SSL_CTX_check_private_key(mc_ctx) != 1){ /* 检查私钥和公钥是否配对 */
                        mc_free_startup();
                        mc_err("Error %s:%d %u: failed to read certificate or privatekey file\n", __FILE__, __LINE__, getpid());
       		}
                if(mc_startup->s_configinfo.c_cipher &&
                	SSL_CTX_set_cipher_list(mc_ctx, mc_startup->s_configinfo.c_cipher) != 1){ /* 设置加密算法，如果用户不设置则是默认值 */
                        mc_free_startup();
                        mc_err("Error %s:%d %u: failed to set cipher string\n", __FILE__, __LINE__, getpid());
               	}
   	} 
	i = mc_startup->s_configinfo.c_schd.s_maxprocs * MC_CHILDPROC_SIZE;
	if((p = mmap(NULL, i, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED){
                if((fd = open("/dev/zero", O_RDWR)) == -1){
			mc_free_startup();
			mc_err("Error %s:%d %u: failed to open /dev/zero\n", __FILE__, __LINE__, getpid());
                }
                if((p = mmap(NULL, i, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
                        mc_close(fd);
			mc_free_startup();
			mc_err("Error %s:%d %u: out of memory\n", __FILE__, __LINE__, getpid());
                }
                mc_close(fd);
        }
        mc_memset((mc_startup->s_childprocs = p), 0, i);
	fclose(mc_stderr);
	mc_close(mc_listenfd);
	mc_close(STDERR_FILENO); /* logfile所指的文件描述符 */
	mc_stdout = mc_stderr = NULL;
	if((fd = open(mc_startup->s_configinfo.c_logfile, O_WRONLY | O_CREAT, MC_FILE_MODE)) == -1 || !(mc_stderr = fdopen(fd, "a"))){
                mc_free_startup();
		exit(1); /* 此处没法打印错误信息 */
        }
	mc_stdout = mc_stderr;
	setvbuf(mc_stdin, NULL, _IONBF, 0);
        setvbuf(mc_stderr, NULL, _IONBF, 0);
#if HAVE_SETUID 
        if(setgid(mc_startup->s_configinfo.c_gid) || setuid(mc_startup->s_configinfo.c_uid)){
                mc_free_startup();
                mc_err("Error %s:%d %u: failed to setgid or setuid: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
        }
#endif
	switch((mc_schdid = fork())){
        case -1:
                mc_free_startup();
                mc_err("Error %s:%d %u: failed to create schedule process\n", __FILE__, __LINE__, getpid());
        case 0:
                mc_schedule();
                break;
        default:
                break;
        }
	if((mc_listenfd = mc_get_sockfd(mc_startup->s_configinfo.c_domain, SOCK_STREAM, 0)) == -1){
        	mc_free_startup();
                mc_err("Error %u: failed to get socket file descriptor for listening: %s\n", getpid(), strerror(errno));
      	}
        for(i = 0; i < mc_startup->s_configinfo.c_schd.s_medianprocs; i++)
        	mc_creat_child();
}

int
main(int argc, char *argv[])
{
	char	*p;
	int	i, fd;
	socklen_t       addrlen;
        struct sockaddr_storage addr;

#if HAVE_SETLOCALE 
	setlocale(LC_TIME, "C");
#endif
	if(getuid() != 0) /* 程序必须以root运行 */
		mc_err("Error %s:%d %u: please run as root\n", __FILE__, __LINE__, getpid());
	if((mc_startup = mc_deal_configuration(argc, argv)) != NULL){ 
		if(mc_startup->s_version)
			mc_show_version();
		if(mc_startup->s_check)
			mc_check_environment();
		mc_set_startup();
		if(mc_startup->s_usessl){
			SSL_load_error_strings();
			SSLeay_add_ssl_algorithms();
			if((mc_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL){
				mc_free_startup();	
				mc_err("Error %s:%d %u: failed to ssl_ctx_new\n", __FILE__, __LINE__, getpid());
			}
			SSL_CTX_set_options(mc_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
			if(SSL_CTX_use_certificate_chain_file(mc_ctx, mc_startup->s_configinfo.c_certfile) != 1 || /* 公钥 */
				SSL_CTX_use_PrivateKey_file(mc_ctx, mc_startup->s_configinfo.c_keyfile, SSL_FILETYPE_PEM) != 1 ||  /* 私钥 */
				SSL_CTX_check_private_key(mc_ctx) != 1){ /* 检查私钥和公钥是否配对 */
				mc_free_startup();
				mc_err("Error %s:%d %u: failed to read certificate file\n", __FILE__, __LINE__, getpid());
			}
			if(mc_startup->s_configinfo.c_cipher && 
				SSL_CTX_set_cipher_list(mc_ctx, mc_startup->s_configinfo.c_cipher) != 1){ /* 设置加密算法，如果用户不设置则是默认值 */
				mc_free_startup();
				mc_err("Error %s:%d %u: failed to set cipher string\n", __FILE__, __LINE__, getpid());
			}
		}
		if(mc_init_mem() == -1){
                	mc_free_startup();
                	mc_err("Error %s:%d %u: failed to init shared memory\n", __FILE__, __LINE__, getpid());
        	}
        	mc_daemon();
		if((mc_listenfd = mc_get_sockfd(mc_startup->s_configinfo.c_domain, SOCK_STREAM, 0)) == -1){
                	mc_free_startup();
                	mc_err("Error %u: failed to get socket file descriptor for listening: %s\n", getpid(), strerror(errno));
        	}
		for(i = 0; i < mc_startup->s_configinfo.c_schd.s_medianprocs; i++)
                	mc_creat_child();
		for( ; ; ){ /* 无限循环，父进程不断的接受请求 */
			addrlen = sizeof(addr);
			if((fd = accept(mc_listenfd, MC_SA(&addr), &addrlen)) > 0 && mc_send_fd(fd) == -1){ 
				mc_warn("Error %s:%d %u: failed to deal request from %s\n", __FILE__, __LINE__, getpid(), 
					p = mc_print_ip(MC_SA(&addr)));
				free(p);
			}
#if 0 
			mc_warn("Debug %u: accept: fd = %d, quit = %d, restart = %d\n", getpid(), fd, mc_quit, mc_restart);
#endif
			switch(fd){
			case -1:
				if(errno != EINTR || !(mc_quit || mc_restart))
					break;
				for(i = 0; i < mc_startup->s_configinfo.c_schd.s_maxprocs; i++){ /* 杀死所有正在运行的处理进程 */
                			if(mc_startup->s_childprocs[i].c_pid > 0){
						mc_close(mc_startup->s_childprocs[i].c_fd);
                        			kill(mc_startup->s_childprocs[i].c_pid, SIGINT);
					}
        			}
        			kill(mc_schdid, SIGINT);
        			while(mc_wait(NULL) > 0)
                			;
				if(mc_quit){ /* 退出 */
					mc_free_startup();
					exit(0);	
				}
				mc_reset();
				mc_restart = 0; /* BUG: 如果在重启过程中再次发生的SIGHUP信号会因为清零操作而被忽略 */
				break;
			default: /* 父进程不处理请求 */
				mc_close(fd);
				break;
			}
		}
	}else
		mc_err("Error %s:%d %u: failed to deal configuration parameters\n", __FILE__, __LINE__, getpid());
	return 0;
}
