#ifndef _MC_MC_H
#define _MC_MC_H

#include	"../config.h"

#if STDC_HEADERS
#include	<errno.h>
#include	<stdio.h>
#include	<ctype.h>
#include	<signal.h>
#include	<string.h>
#include	<stdlib.h>
#include	<locale.h>
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
#include	<pthread.h>
#include	<sys/un.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<sys/types.h>	
#include	<sys/select.h>
#include	<arpa/inet.h>
#include	<netinet/in.h>
#include	<sys/socket.h>
#include	<openssl/ssl.h>
#include	<openssl/err.h>
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
#define RLIMIT_NPROC	7	/* 一般不考虑使用 */
#define RLIMIT_NOFILE	8
#endif

#if MC_HAVE_SEM
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

#ifndef MC_FD_PRIVATE
#define MC_FD_PRIVATE	10	
#endif

#ifndef MC_max
#define MC_max(x, y)	((x) > (y) ? (x) : (y))
#endif

#ifndef MC_min
#define MC_min(x, y)	((x) < (y) ? (x) : (y))
#endif

#endif
