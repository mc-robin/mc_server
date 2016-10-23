#ifndef _MC_CONFIGINFO_H
#define _MC_CONFIGINFO_H

#include	"mc.h"

#ifndef MC_CONFIG_FILE
#define MC_CONFIG_FILE	"/etc/mc_echo.conf"
#endif

#ifndef MC_PID_FILE
#define MC_PID_FILE	"/var/run/mc_echo.pid"
#endif

#ifndef MC_LOG_FILE
#define MC_LOG_FILE	"/var/log/mc_echo.log"
#endif

#define MC_SCHEDINFO_SIZE       (sizeof(struct mc_schedinfo))
struct mc_schedinfo{
        int    	s_maxprocs;	/* 主进程最多能创建的进程数目 */
        int     s_medianprocs;  /* 预先创建的进程数，同时也是服务器努力维护的进>程数目 */
        int     s_maxfds;	/* 处理进程能处理的最多的请求数目 */
        int     s_thresholdfds_u; /* 请求数目上限 */
        int     s_thresholdfds_l; /* 请求数目下限 */
};

#define MC_CONFIGINFO_SIZE	(sizeof(struct mc_configinfo))
struct mc_configinfo{
	uid_t	c_uid;
	gid_t	c_gid;
	time_t	c_cycle;
	int	c_domain;
	int	c_backlog;
	char	*c_cipher;	/* 自定义加密算法字符串 */
	char	*c_logfile;
	char	*c_pidfile;
	char	*c_keyfile;
	char	*c_certfile;	/* 证书文件路径 */
	in_port_t	c_port;
	struct mc_schedinfo	c_schd;
};

#define MC_CHILDPROC_SIZE       (sizeof(struct mc_childproc))
typedef struct mc_childproc     *mc_childproc;
struct mc_childproc{
        int     c_fd;     /* 负数-闲置进程，0未用，正数-处理进程 */
        int     c_cnt;
        pid_t   c_pid;
};

#define MC_LOCKKEY_SIZE (sizeof(struct mc_lockkey))
struct mc_lockkey{
        pid_t   l_pid;    /* 占用锁的进程，没有则为0 */
	sem_t	*l_key;
};

#define MC_STARTUP_SIZE (sizeof(struct mc_startup_set))
typedef struct mc_startup_set   *mc_startup_set;
struct mc_startup_set{
        int     s_check;
	int	s_usessl;	/* 只要设定了certfile就会使用ssl */
        int     s_version;
        int     *s_newproc;
        char    *s_configfile;
        mc_childproc    s_childprocs;
        struct mc_lockkey       s_lock;
        struct mc_configinfo    s_configinfo;   /* 配置参数 */
};

#ifndef MC_DIGIT_SET
#define MC_DIGIT_SET(x, y)      { if((y)){ ((x)) = atoi(y); free((y)); } else{ mc_free_startup(); \
					mc_err("Error %s:%d %u: cannot strdup NULL\n", __FILE__, __LINE__, getpid()); }}
#endif

#ifndef MC_STRING_SET
#define MC_STRING_SET(x, y)     { if((y)){ (x) = (y); } else{ mc_free_startup(); \
                                        mc_err("Error %s:%d %u: cannot strdup NULL\n", __FILE__, __LINE__, getpid()); }}
#endif

#ifndef MC_USER_SET
#define MC_USER_SET(x, y)       { if((y)){ (x) = mc_get_uid((y)); free((y)); } else{ mc_free_startup(); \
                                        mc_err("Error %s:%d %u: cannot strdup user string NULL\n", __FILE__, __LINE__, getpid()); }}   
#endif

#ifndef MC_GROUP_SET
#define MC_GROUP_SET(x, y)      { if((y)){ (x) = mc_get_gid((y)); free((y)); } else{ mc_free_startup(); \
                                        mc_err("Error %s:%d %u: cannot strdup group string NULL\n", __FILE__, __LINE__, getpid()); }}
#endif

#ifndef MC_DOMAIN_SET
#define MC_DOMAIN_SET(x, y)     { if((y)){ (x) = mc_get_domain((y)); free((y)); } else{ mc_free_startup(); \
                                        mc_err("Error %s:%d %u: cannot strdup ipversion string NULL\n", __FILE__, __LINE__, getpid()); }}      

#endif

extern FILE     *yyin;
extern mc_startup_set	mc_startup;

static inline void
mc_free_startup(void)
{
        if(mc_startup->s_configfile)
                free(mc_startup->s_configfile);
        if(mc_startup->s_configinfo.c_logfile)
                free(mc_startup->s_configinfo.c_logfile);
        if(mc_startup->s_configinfo.c_pidfile)
                free(mc_startup->s_configinfo.c_pidfile);
	if(mc_startup->s_configinfo.c_keyfile)
		free(mc_startup->s_configinfo.c_keyfile);
	if(mc_startup->s_configinfo.c_certfile)
		free(mc_startup->s_configinfo.c_certfile);	
        if(mc_startup->s_newproc)
                munmap(mc_startup->s_newproc, sizeof(int));
        if(mc_startup->s_lock.l_key)
		munmap(mc_startup->s_lock.l_key, sizeof(sem_t));
        if(mc_startup->s_childprocs)
                munmap(mc_startup->s_childprocs, mc_startup->s_configinfo.c_schd.s_maxprocs * MC_CHILDPROC_SIZE);
        free(mc_startup);
        mc_startup = NULL;
}


static inline void
mc_usage(void)
{
        fprintf(stderr, "Usage: mc_echo [-46cCvV] [-fF configuration file] [-gG group] [-uU user] [-pP port]\n");
}

/*
 * configure.c
 */
int     yyparse(void);
uid_t	mc_get_uid(const char *user);
gid_t   mc_get_gid(const char *group);
int	mc_get_domain(const char *ipversion);
struct group    *mc_getgrgid(gid_t gid);
struct passwd   *mc_getpwuid(uid_t uid);
struct group    *mc_getgrnam(const char *name);
struct passwd   *mc_getpwnam(const char *name);
mc_startup_set mc_deal_configuration(int argc, char *argv[]);

/*
 * interface.c
 */
int     mc_lock(void);
int     mc_unlock(void);
int     mc_memcmp(const void *s1, const void *s2, size_t n);
void    mc_print_time(void);
void    mc_err(const char *fmt, ...);
void    mc_warn(const char *fmt, ...);
void    *mc_memset(void *s, int c, size_t n);
void    *mc_memchr(const void *s, int c, size_t n);
void    *mc_memcpy(void *dst, const void *src, size_t n);
char    *mc_strdup(const char *s);
char    *mc_strchr(const char *s, int c);
char    *mc_strrchr(const char *s, int c);
char    *mc_stndup(const char *s, size_t n);
char    *mc_strstr(const char *s1, const char *s2);
char    *mc_strpbrk(const char *s1, const char *s2);
size_t  mc_strspn(const char *s1, const char *s2);
size_t  mc_strcspn(const char *s1, const char *s2);

#endif
