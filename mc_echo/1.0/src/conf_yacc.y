%{
#undef 	YYSTACKSIZE
#define YYSTACKSIZE	5000
#include	"configure.h" 
%}

%union{
	char	*dstr;
}

%token PORT
%token USER
%token GROUP
%token CIPHER
%token BACKLOG
%token LOGFILE
%token PIDFILE
%token KEYFILE
%token CERTFILE
%token IPVERSION
%token CYCLETIME
%token MAXREQUESTS
%token MAXPROCESSES
%token PROCESSCREAT
%token UPPERTHRESHOLD
%token LOWERTHRESHOLD
%token OR
%token OBRACE
%token EBRACE
%token <dstr> STRING

%%

config_list: config
	   | config_list config 
	   ; 

config: vars_set
	;

vars_set: USER	OBRACE STRING EBRACE	{ MC_USER_SET(mc_startup->s_configinfo.c_uid, $3) }
   	| GROUP OBRACE STRING EBRACE	{ MC_GROUP_SET(mc_startup->s_configinfo.c_gid, $3) }
	| PORT 	OBRACE STRING EBRACE	{ MC_DIGIT_SET(mc_startup->s_configinfo.c_port, $3) }
	| CIPHER  OBRACE STRING EBRACE	{ MC_STRING_SET(mc_startup->s_configinfo.c_cipher, $3) }
	| BACKLOG OBRACE STRING EBRACE	{ MC_DIGIT_SET(mc_startup->s_configinfo.c_backlog, $3) }
 	| LOGFILE OBRACE STRING EBRACE	{ MC_STRING_SET(mc_startup->s_configinfo.c_logfile, $3) }
	| PIDFILE OBRACE STRING EBRACE	{ MC_STRING_SET(mc_startup->s_configinfo.c_pidfile, $3) } 
	| KEYFILE OBRACE STRING EBRACE 	{ MC_STRING_SET(mc_startup->s_configinfo.c_keyfile, $3) }
	| CERTFILE  OBRACE STRING EBRACE { MC_STRING_SET(mc_startup->s_configinfo.c_certfile, $3) }
	| CYCLETIME OBRACE STRING EBRACE { MC_DIGIT_SET(mc_startup->s_configinfo.c_cycle, $3) }
	| IPVERSION OBRACE STRING EBRACE { MC_DOMAIN_SET(mc_startup->s_configinfo.c_domain, $3) }
	| MAXREQUESTS OBRACE STRING EBRACE { MC_DIGIT_SET(mc_startup->s_configinfo.c_schd.s_maxfds, $3) }
	| MAXPROCESSES OBRACE STRING EBRACE { MC_DIGIT_SET(mc_startup->s_configinfo.c_schd.s_maxprocs, $3) }
	| PROCESSCREAT OBRACE STRING EBRACE { MC_DIGIT_SET(mc_startup->s_configinfo.c_schd.s_medianprocs, $3) }
	| UPPERTHRESHOLD OBRACE STRING EBRACE { MC_DIGIT_SET(mc_startup->s_configinfo.c_schd.s_thresholdfds_u, $3) }
	| LOWERTHRESHOLD OBRACE STRING EBRACE { MC_DIGIT_SET(mc_startup->s_configinfo.c_schd.s_thresholdfds_l, $3) }
	;

%%

int
yyerror(char *s)
{
	fprintf(stderr, "%s\n", s);
}
