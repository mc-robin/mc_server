#ifndef _MC_SERVER_H
#define _MC_SERVER_H

#include	"../config.h"

#if STDC_HEADERS
#include	<errno.h>
#include	<stdio.h>
#include	<ctype.h>
#include	<signal.h>
#include	<string.h>
#include	<stdlib.h>
#include	<locale.h>
#include	<setjmp.h>
#include	<string.h>
#include	<stdarg.h>
#endif

#if (HAVE_UNISTD_H && HAVE_SYS_TYPES_H)
#define MC_POSIX_HEADERS	1
#include	<pwd.h>
#include	<grp.h>
#include	<fcntl.h>
#include	<netdb.h>
#include	<unistd.h>
#include	<sys/un.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<sys/types.h>	
#include	<sys/select.h>
#include	<arpa/inet.h>
#include	<netinet/in.h>
#include	<sys/socket.h>
#endif

#if defined sigsetjmp || HAVE_SIGSETJMP
#define MC_HAVE_SIGSETJMP	1
#endif

#if HAVE_STDINT_H
#include	<stdint.h>
#endif

#if HAVE_DIRENT_H
#include	<dirent.h>
#define NAMLEN(dirent)	(strlen((dirent)->d_name))
#else
#define dirent direct
#define NAMLEN(dirent)	((dirent)->d_namlen)
#if HAVE_SYS_NDIR.H
#include	<sys/ndir.h>
#endif
#if HAVE_SYS_DIR_H
#include	<sys/dir.h>
#endif
#if HAVE_NDIR_H
#include	<ndir.h>
#endif
#endif

#if HAVE_SYS_WAIT_H
#include	<sys/wait.h>
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val)	((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(stat_val)	(((stat_val) & 0xFF) == 0)
#endif

#if (HAVE_STRINGS_H && HAVE_BCOPY)
#define MC_HAVE_BSD_STRING	1
#include	<strings.h>
#endif 

#if (HAVE_SYS_RESOURCE_H && HAVE_GETRLIMIT)
#define MC_HAVE_INCREASE_LIMIT	1
#include	<sys/resource.h>
#else	
#define RLIMIT_NPROC	7
#define RLIMIT_NOFILE	8
#endif

#if HAVE_SEM
#include	<semaphore.h>
#endif

#if HAVE_MEMSET
#define MC_HAVE_MEM_STRING	1
#endif

#if HAVE_STRCHR
#define MC_HAVE_STR_STRING	1
#endif

#if TIME_WITH_SYS_TIME
#include	<sys/time.h>
#include	<time.h>
#else
#if HAVE_SYS_TIME_H
#include	<sys/time.h>
#else
#include	<time.h>
#endif
#endif

#if !S_IRUSR
#if S_IREAD
#define S_IRUSR	S_IREAD
#else
#define S_IRUSR	00400
#endif
#endif

#if !S_IWUSR
#if S_IWRITE
#define S_IWUSR	S_IWRITE
#else
#define S_IWUSR	00200
#endif
#endif

#if !S_IXUSR
#if S_IEXEC
#define S_IXUSR S_IEXEC
#else
#define S_IXUSR 00100
#endif
#endif

#ifdef STAT_MACROS_BROKEN
#undef S_ISBLK
#undef S_ISCHR
#undef S_ISDIR
#undef S_ISFIFO
#undef S_ISLNK
#undef S_ISMPB
#undef S_ISMPC
#undef S_ISNWK
#undef S_ISREG
#undef S_ISSOCK
#endif 

#if (!defined(S_ISBLK) && defined(S_IFBLK))
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#endif
#if (!defined(S_ISCHR) && defined(S_IFCHR))
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif
#if (!defined(S_ISDIR) && defined(S_IFDIR))
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#if (!defined(S_ISREG) && defined(S_IFREG))
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#if (!defined(S_ISFIFO) && defined(S_IFIFO))
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#if (!defined(S_ISLNK) && defined(S_IFLNK))
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
#if (!defined(S_ISSOCK) && defined(S_IFSOCK))
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif
#if (!defined(S_ISMPB) && defined(S_IFMPB))
#define S_ISMPB(m) (((m) & S_IFMT) == S_IFMPB)
#define S_ISMPC(m) (((m) & S_IFMT) == S_IFMPC)
#endif
#if (!defined(S_ISNWK) && defined(S_IFNWK)) 
#define S_ISNWK(m) (((m) & S_IFMT) == S_IFNWK)
#endif

#define MC_FILE_MODE	0666

#if (HAVE_KQUEUE && HAVE_SYS_EVENT_H)
#define MC_USE_KQUEUE	1
#include	<sys/event.h>
#elif (HAVE_EPOLL_CTL && HAVE_SYS_EPOLL_H)
#define MC_USE_EPOLL	1	
#include	<sys/epoll.h>
#elif (HAVE_SYS_DEVPOLL_H && defined (__sun))
#define MC_USE_DEVPOLL	1	
#include	<sys/devpoll.h>
#elif (HAVE_POLL && (HAVE_SYS_POLL_H || POLL_H))
#define MC_USE_POLL	1	
#else
#define MC_NONE_IO	1
#endif 

#if HAVE_POLL_H
#include	<poll.h>
#else
#include	<sys/poll.h>
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO	0
#endif

#ifndef STDOUT_FILENO	
#define STDOUT_FILENO	1
#endif

#ifndef STDERR_FILENO	
#define STDERR_FILENO	2
#endif

#ifndef BUFSIZ
#define BUFSIZ	4096	
#endif 	 

#ifndef MC_EVENT_IN
#define MC_EVENT_IN	1	
#endif

#ifndef MC_EVENT_OUT
#define MC_EVENT_OUT	2	
#endif

#ifndef MC_EVENT_ERR
#define MC_EVENT_ERR	4	
#endif

#ifndef MC_FD_PRIVATE
#define MC_FD_PRIVATE	10	
#endif

#ifndef SA_INTERRUPT	
#define	SA_INTERRUPT	0
#endif  

#ifndef AF_LOCAL
#define AF_LOCAL	AF_UNIX
#endif

#ifndef PF_LOCAL
#define PF_LOCAL	PF_UNIX
#endif

#ifndef MC_SA
#define MC_SA(x)	((struct sockaddr *)(x))
#endif

#ifndef MC_SA4
#define MC_SA4(x)	((struct sockaddr_in *)(x))
#endif

#ifndef MC_SA6
#define MC_SA6(x)	((struct sockaddr_in6 *)(x))
#endif

#ifndef MC_CONFIG_FILE
#define MC_CONFIG_FILE	"/etc/mc_echo.conf"
#endif

#ifndef MC_PID_FILE
#define MC_PID_FILE	"/var/run/mc_echo.pid"
#endif

#ifndef MC_max
#define MC_max(x, y)	((x) > (y) ? (x) : (y))
#endif

#ifndef MC_min
#define MC_min(x, y)	((x) < (y) ? (x) : (y))
#endif

#define MC_CHILDREN_SIZE	(sizeof(struct mc_children))
typedef struct mc_children	*mc_children;
struct mc_children{ 
	int	fd;	
	int	cnt;	
	pid_t	pid;	
};

#define MC_SCHEDULE_SIZE	(sizeof(struct mc_schedule))
struct mc_schedule{
	int	procs;	
	int	maxproc;
	int	maxfds;	
	int	thresholdfds_u;	
	int	thresholdfds_l;	
};

#define MC_LOCKKEY_SIZE	(sizeof(struct mc_lockkey))
struct mc_lockkey{
	pid_t	pid;	
	sem_t	*key; 	
};

#define MC_STARTUP_SIZE	(sizeof(struct mc_startup_set))
typedef struct mc_startup_set	*mc_startup_set;
struct mc_startup_set{
        uid_t   s_uid;    
        gid_t   s_gid;    
	time_t	s_cycle;  
	int	s_check;  
        int     s_domain; 
        int     s_backlog;      
        int     s_version;      
	char	*s_logfile;	
        char    *s_rootpath;   	
        char    *s_conffile;   	
	int	*s_creatreq;	
        in_port_t	s_port; 
	mc_children	s_children; 	
        struct mc_lockkey	s_lock; 
	struct mc_schedule	s_schd; 
};

typedef struct mc_pollfd	*mc_pollfd;
struct mc_pollfd{ 
	int	fd;
	short	revents;	
};

#define MC_EVENT_SIZE	(sizeof(struct mc_event))
typedef struct mc_event	*mc_event;
struct mc_event{
	int	nfds;	
	int	maxfds;	
	int	offset, events; 
#ifdef	MC_USE_KQUEUE
	int	fd;
	struct kevent	*fds;
#endif
#ifdef MC_USE_EPOLL
	int	fd;	
	struct epoll_event	*fds;
#endif
#ifdef MC_USE_DEVPOLL
	int	fd;
	struct pollfd 	*fds;
#endif
#ifdef 	MC_USE_POLL
	struct	pollfd	*fds; 
#endif
	int	(*free)(mc_event evp);
	int	(*poll)(mc_event evp, int timeout);	
	int	(*add)(mc_event evp, int fd, int flags); 
	int	(*del)(mc_event evp, int fd, int flags);		
	int	(*traverse)(mc_event evp, mc_pollfd pollp);		
}; 

extern mc_event	mc_evp;
extern FILE	*mc_stdin;
extern FILE	*mc_stdout;
extern FILE	*mc_stderr;
extern int	mc_schdid;
extern int	mc_recvfd;
extern int 	mc_listenfd;
extern sigjmp_buf	mc_env;
extern volatile int 	mc_restart;
extern mc_startup_set	mc_startup;
extern mc_children	mc_request_info;

static inline void
mc_free_startup(void)
{
        if(mc_startup->s_conffile)
                free(mc_startup->s_conffile);
	if(mc_startup->s_logfile)
                free(mc_startup->s_logfile);
        if(mc_startup->s_rootpath)
                free(mc_startup->s_rootpath);
        if(mc_startup->s_creatreq)
                munmap(mc_startup->s_creatreq, sizeof(int));
        if(mc_startup->s_children)
                munmap(mc_startup->s_children, mc_startup->s_schd.maxproc * MC_CHILDREN_SIZE);
        if(mc_startup->s_lock.key){
                sem_destroy(mc_startup->s_lock.key);
                munmap(mc_startup->s_lock.key, sizeof(sem_t));
        }
        free(mc_startup);
	mc_startup = NULL;
}

static inline void
mc_show_version(void)
{
	fprintf(stderr, "%s/%s: %s\n", PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_BUGREPORT);
	mc_free_startup();
	exit(0);
}

static inline void
usage(void)
{
        fprintf(stderr, "Usage: mc_talkd [-46cCvV] [-fF configuration file] [-gG group] [-uU user] [-pP port]\n");
}

int	mc_lock(void);
int	mc_unlock(void);
int	mc_memcmp(const void *s1, const void *s2, size_t n);
uid_t	mc_get_uid(const char *user);
gid_t	mc_get_gid(const char *group);
void	mc_print_time(void);
void	mc_err(const char *fmt, ...);
void	mc_warn(const char *fmt, ...);
void	*mc_memset(void *s, int c, size_t n);
void	*mc_memchr(const void *s, int c, size_t n);
void	*mc_memcpy(void *dst, const void *src, size_t n);
char	*mc_strdup(const char *s);
char	*mc_strchr(const char *s, int c);
char	*mc_strrchr(const char *s, int c);
char 	*mc_stndup(const char *s, size_t n);
char	*mc_strstr(const char *s1, const char *s2);
char	*mc_strpbrk(const char *s1, const char *s2);
size_t	mc_strspn(const char *s1, const char *s2);
size_t	mc_strcspn(const char *s1, const char *s2);
mc_event	mc_init_event(int maxfds);
#if MC_USE_DEVPOLL
int	mc_event_devpoll_free(mc_event p);
int	mc_event_devpoll_poll(mc_event p, int timeout);
int	mc_event_devpoll_add(mc_event p, int fd, int flags);
int	mc_event_devpoll_del(mc_event p, int fd, int flags);
int	mc_event_devpoll_traverse(mc_event p, mc_pollfd pollp);
#endif
#if MC_USE_EPOLL
int	mc_event_epoll_free(mc_event p);
int	mc_event_epoll_poll(mc_event p, int timeout);
int	mc_event_epoll_add(mc_event p, int fd, int flags);
int	mc_event_epoll_del(mc_event p, int fd, int flags);
int	mc_event_epoll_traverse(mc_event p, mc_pollfd pollp);
#endif
#if MC_USE_KQUEUE
int	mc_event_kqueue_free(mc_event p);
int	mc_event_kqueue_poll(mc_event p, int timeout);
int	mc_event_kqueue_add(mc_event p, int fd, int flags);
int	mc_event_kqueue_del(mc_event p, int fd, int flags);
int	mc_event_kqueue_traverse(mc_event p, mc_pollfd pollp);
#endif
#if MC_USE_POLL
int	mc_event_poll_free(mc_event p);
int	mc_event_poll_poll(mc_event p, int timeout);
int	mc_event_poll_add(mc_event p, int fd, int flags);
int	mc_event_poll_del(mc_event p, int fd, int flags);
int	mc_event_poll_traverse(mc_event p, mc_pollfd pollp);
#endif

pid_t	mc_wait(int *status);
int	mc_close(int fd);
int	mc_init_sig(int type);
int	mc_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t	mc_read(int fd, void *buf, size_t count);
ssize_t	mc_write(int fd, const void *buf, size_t count);
ssize_t mc_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t	mc_sendmsg(int sockfd, const struct msghdr *msg, int flags);
struct group	*mc_getgrgid(gid_t gid);
struct passwd	*mc_getpwuid(uid_t uid);
struct group	*mc_getgrnam(const char *name);
struct passwd	*mc_getpwnam(const char *name);
FILE	*mc_fopen(const char *path, const char *mode);

mc_startup_set	mc_deal_configuration(int argc, char *argv[]);

void	mc_daemon(void);
int	mc_init_mem(void);
int	mc_creat_child(void);
int	mc_send_fd(int fd);
int	mc_get_sockfd(int domain, int type, int protocol);
char	*mc_print_ip(struct sockaddr *addr);

#endif
