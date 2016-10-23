#include	"configure.h"

mc_startup_set	mc_startup;

static mc_startup_set	mc_init_startup(void);
static int	mc_deal_arg(int argc, char *argv[]);

static mc_startup_set
mc_init_startup(void)
{
	mc_startup_set	p;

	if((p = calloc(1, MC_STARTUP_SIZE)) == NULL)
		return NULL;
	p->s_configinfo.c_domain = AF_UNSPEC;
	return p;
}

static int
mc_deal_arg(int argc, char *argv[])
{
	int	i, c, s;

	for(i = 1; i < argc; i += (s + 1)){
		if(argv[i][0] != '-') 
			goto err;
		s = 0;
		while((c = *++argv[i])){
			switch(c){
			case '4':
				mc_startup->s_configinfo.c_domain = AF_INET;
				break;
			case '6':
				mc_startup->s_configinfo.c_domain = AF_INET6;
				break;
			case 'f':
			case 'F':
				s++;
				if(argv[i + s] == NULL)
					goto err;
				if((mc_startup->s_configfile = mc_strdup(argv[i + s])) == NULL)
					goto err;
				break;
			case 'p':
			case 'P':
				s++;
				if(argv[i + s] == NULL)
					goto err;
				if(!(mc_startup->s_configinfo.c_port = atoi(argv[i + s]))) 
					goto err;
				break;	
			case 'u':
			case 'U':
				s++;
				if(!(mc_startup->s_configinfo.c_uid = mc_get_uid(argv[i + s])))
					goto err;
				break;
			case 'g':
			case 'G':
				s++;
				if(!(mc_startup->s_configinfo.c_gid = mc_get_gid(argv[i + s])))
					goto err;
				break;
			case 'v':
			case 'V':
				mc_startup->s_version = 1;
				break;
			case 'c':
			case 'C':
				mc_startup->s_check = 1;
				break;
			default:
				goto err;
			}
		}	
	}
	return 0;
err:
	mc_warn("Error %s:%d %u: illegal option '%s'\n", __FILE__, __LINE__, getpid(), argv[i]);
	return -1;
}

uid_t
mc_get_uid(const char *user)
{
        struct passwd   *up;

        if(user == NULL)
                return 0;
        if(up = mc_getpwnam(user)){
                return up->pw_uid;
        }else if(up = mc_getpwuid(atoi(user)))
                return up->pw_uid;
        return 0;
}

gid_t
mc_get_gid(const char *group)
{
        struct group    *gp;

        if(group == NULL)
                return 0;
        if(gp = mc_getgrnam(group)){
                return gp->gr_gid;
        }else if(gp = mc_getgrgid(atoi(group)))
                return gp->gr_gid;
        return 0;
}

int
mc_get_domain(const char *ipversion)
{
        if(strcmp(ipversion, "ipv4") == 0){
                return AF_INET;
        }else if(strcmp(ipversion, "ipv6") == 0)
                return AF_INET6;
        return AF_UNSPEC;
}

struct passwd   *
mc_getpwnam(const char *name)
{
        struct passwd   *up;

retry:
        if((up = getpwnam(name)) == NULL && errno == EINTR)
                goto retry;
        return up;
}

struct passwd   *
mc_getpwuid(uid_t uid)
{
        struct passwd   *up;

retry:
        if((up = getpwuid(uid)) == NULL && errno == EINTR)
                goto retry;
        return up;
}

struct group    *
mc_getgrnam(const char *name)
{
        struct group    *gp;

retry:
        if((gp = getgrnam(name)) == NULL && errno == EINTR)
                goto retry;
        return gp;
}

struct group    *
mc_getgrgid(gid_t gid)
{
        struct group    *gp;

retry:
        if((gp = getgrgid(gid)) == NULL && errno == EINTR)
                goto retry;
        return gp;
}

mc_startup_set
mc_deal_configuration(int argc, char *argv[])
{
	if((mc_startup = mc_init_startup()) == NULL){
		mc_warn("Error %s:%d %u: failed to init startup parameter: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return NULL;
	}
	if(mc_deal_arg(argc, argv) == -1){
		mc_usage();
		mc_free_startup();
		return NULL;
	}
	if(mc_startup->s_configfile == NULL && (mc_startup->s_configfile = mc_strdup(MC_CONFIG_FILE)) == NULL){
		mc_free_startup();
		mc_warn("Error %s:%d %u: out of memory: %s\n", __FILE__, __LINE__, getpid(), strerror(errno));
		return NULL;
	}
	if(mc_startup->s_configfile[0] != '/'){
		mc_warn("Error %s:%d %u: '%s': not absolute path\n", __FILE__, __LINE__, getpid(), mc_startup->s_configfile);
		mc_free_startup();
		return NULL;
	}
	if((yyin = fopen(mc_startup->s_configfile, "r")) == NULL){
		mc_warn("Error %s:%d %u: failed to open configure file '%s': %s\n", __FILE__, __LINE__, getpid(), 
			mc_startup->s_configfile, strerror(errno));
		mc_free_startup();
		return NULL;
	}
	yyparse();
	fclose(yyin);
	return mc_startup;
}
