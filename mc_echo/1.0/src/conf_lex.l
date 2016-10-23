%{
#include	"configure.h"
#include	"conf_yacc.h"
%}

%%

[Uu][Ss][Ee][Rr]	{ return USER; }
[Pp][Oo][Rr][Tt]	{ return PORT; }
[Gg][Rr][Oo][Uu][Pp]	{ return GROUP; }
[Cc][Ii][Pp][Hh][Ee][Rr]	{ return CIPHER; }
[Bb][Aa][Cc][Kk][Ll][Oo][Gg]	{ return BACKLOG; }
[Ll][Oo][Gg][Ff][Ii][Ll][Ee]	{ return LOGFILE; }
[Pp][Ii][Dd][Ff][Ii][Ll][Ee]	{ return PIDFILE; }
[Kk][Ee][Yy][Ff][Ii][Ll][Ee]	{ return KEYFILE; }
[Cc][Ee][Rr][Tt][Ff][Ii][Ll][Ee] 	{ return CERTFILE; }
[Ii][Pp][Vv][Ee][Rr][Ss][Ii][Oo][Nn]	{ return IPVERSION; }
[Cc][Yy][Cc][Ll][Ee][Tt][Ii][Mm][Ee]	{ return CYCLETIME; }
[Mm][Aa][Xx][Rr][Ee][Qq][Uu][Ee][Ss][Tt][Ss]	{ return MAXREQUESTS; }
[Mm][Aa][Xx][Pp][Rr][Oo][Cc][Ee][Ss][Ss][Ee][Ss]	{ return MAXPROCESSES; }
[Pp][Rr][Oo][Cc][Ee][Ss][Ss][Cc][Rr][Ee][Aa][Tt]	{ return PROCESSCREAT; }
[Uu][Pp][Pp][Ee][Rr][Tt][Hh][Rr][Ee][Ss][Hh][Oo][Ll][Dd]	{ return UPPERTHRESHOLD; }
[Ll][Oo][Ww][Ee][Rr][Tt][Hh][Rr][Ee][Ss][Hh][Oo][Ll][Dd]	{ return LOWERTHRESHOLD; }

[ \t\n]		;
#[^\n]*		;	
\|		{ return OR; }
\{		{ return OBRACE; }
\}		{ return EBRACE; }
\"[^\"]*\"	{ yylval.dstr = strndup(yytext + 1, yyleng - 2); return STRING; }

%%
