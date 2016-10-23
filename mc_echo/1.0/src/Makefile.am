SUFFIXES = .c .h .y .l
bin_PROGRAMS = mc_echo
AM_YFLAGS = -d
mc_echo_LDADD = @SEM_LIB@ -ll -lssl
mc_echo_SOURCES = sig.c main.c server.c conf_lex.l conf_yacc.y interface.c configure.c
BUILT_SOURCES = conf_yacc.h
