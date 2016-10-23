#ifndef _MC_SERVER_H
#define _MC_SERVER_H

#include	"configure.h"

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

extern SSL_CTX	*mc_ctx;
extern SSL	**mc_ssl;
extern FILE	*mc_stdin;
extern FILE	*mc_stdout;
extern FILE	*mc_stderr;
extern int	mc_quit;
extern int	mc_schdid;
extern int	mc_recvfd;
extern int 	mc_restart;
extern int 	mc_listenfd;
extern mc_childproc	mc_request_info;

static inline void
mc_show_version(void)
{
	mc_free_startup();
	fprintf(stderr, "%s/%s: %s\n", PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_BUGREPORT);
	exit(0);
}

/*
 * sig.c
 */
pid_t	mc_wait(int *status);
int	mc_close(int fd);
int	mc_init_sig(int type);
ssize_t	mc_read(int fd, void *buf, size_t count);
ssize_t	mc_write(int fd, const void *buf, size_t count);
ssize_t mc_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t	mc_sendmsg(int sockfd, const struct msghdr *msg, int flags);

/*
 * server.c
 */
void	mc_daemon(void);
int	mc_init_mem(void);
int	mc_schedule(void);
int	mc_creat_child(void);
int	mc_send_fd(int fd);
int	mc_get_sockfd(int domain, int type, int protocol);
char	*mc_print_ip(struct sockaddr *addr);

#endif
