AC_PREREQ([2.69])
AC_INIT(mc_echo, 0.9, nnsmgsone@gmail.com)
AC_CONFIG_SRCDIR(src/main.c)
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CC_C_O

AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_MODE_T

AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MEMCMP	# 不能使用memcmp函数，则将memcmp.o添加到LIBOBJS
AC_FUNC_MMAP	# mmap函数存在且能正常工作
AC_FUNC_SELECT_ARGTYPES # 确定select函数的参数类型

AC_HEADER_STDC
AC_HEADER_STAT	# 如果S_ISDIR等定义了却出现误报则定义STAT_MACROS_BROKEN
AC_HEADER_TIME
AC_HEADER_DIRENT
AC_HEADER_SYS_WAIT

AC_CHECK_LIB([pthread], [sem_init], [SEM_LIB=-pthread AC_DEFINE([HAVE_SEM], [1],[semaphore])], \
		[echo "Error: cannot find function sem_init", exit -1])

AC_SUBST(SEM_LIB)

AC_CHECK_HEADERS([poll.h stdint.h strings.h unistd.h sys/types.h sys/event.h sys/epoll.h sys/devpoll.h sys/resource.h])

AC_CHECK_FUNCS([bcopy memset strchr strdup setuid chroot setlocale snprintf sigsetjmp getrlimit poll kqueue epoll_ctl])

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])

AC_OUTPUT
