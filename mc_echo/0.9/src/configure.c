#include	"server.h"

mc_startup_set	mc_startup;

static int	mc_deal_conffile(void);
static int	mc_deal_arg(int argc, char *argv[]);
static mc_startup_set	mc_init_startup(void);

static mc_startup_set
mc_init_startup(void)
{
	mc_startup_set	p;

	if((p = malloc(MC_STARTUP_SIZE)) == NULL)
		return NULL;
	mc_memset(p, 0, sizeof(*p));
	p->s_domain = AF_UNSPEC;
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
				mc_startup->s_domain = AF_INET;
				break;
			case '6':
				mc_startup->s_domain = AF_INET6;
				break;
			case 'f':
			case 'F':
				s++;
				if((mc_startup->s_conffile = mc_strdup(argv[i + s])) == NULL)
					goto err;
				break;
			case 'p':
			case 'P':
				s++;
				if(argv[i + s] == NULL)
					goto err;
				if(!(mc_startup->s_port = atoi(argv[i + s]))) 
					goto err;
				break;	
			case 'u':
			case 'U':
				s++;
				if((mc_startup->s_uid = mc_get_uid(argv[i + s])))
					goto err;
				break;
			case 'g':
			case 'G':
				s++;
				if(!(mc_startup->s_gid = mc_get_gid(argv[i + s])))
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
	mc_warn("Error %u: illegal option '%s'\n", getpid(), argv[i]);
	return -1;
}

static int
mc_deal_conffile(void)
{
	FILE	*fp;
	char	*p, buf[BUFSIZ];

	if((fp = mc_fopen(mc_startup->s_conffile ? mc_startup->s_conffile : MC_CONFIG_FILE, "r")) == NULL){
		mc_warn("Error %u: failed to open configuration file\n", getpid());
		return -1;
	}
	while(fgets(buf, BUFSIZ, fp) != NULL){
		if((p = mc_strchr(buf, '\n')) != NULL) 
			*p = '\0';
		p = buf;
        	p += mc_strcspn(buf, "\t ");
        	if(*p){ 
                	*p = '\0';
                	p++;
                	p += mc_strspn(p, "\t ");
        	}
		if(!*p) 
			goto err_param;
		if(strcmp("rootpath", buf) == 0){
			mc_startup->s_rootpath = mc_strdup(p);	
		}else if(strcmp("ipversion", buf) == 0){
			if(mc_startup->s_domain != AF_UNSPEC) 
				continue;
			if(strcmp(p, "ipv4") == 0){
				mc_startup->s_domain = AF_INET;
			}else if(strcmp(p, "ipv6") == 0)
				mc_startup->s_domain = AF_INET6;
		}else if(strcmp("port", buf) == 0){
			if(mc_startup->s_port) 
				continue;
			if(!(mc_startup->s_port = atoi(p))) 
                        	goto err_param;
		}else if(strcmp("backlog", buf) == 0){
			if(!(mc_startup->s_backlog = atoi(p)))
				goto err_param;
		}else if(strcmp("user", buf) == 0){
			if(mc_restart)
				continue;
			if(mc_startup->s_uid)
				continue;
			if(!(mc_startup->s_uid = mc_get_uid(p)))
				goto err_param;
		}else if(strcmp("group", buf) == 0){
			if(mc_restart)
				continue;
			if(mc_startup->s_gid)
				continue;
			if(!(mc_startup->s_gid = mc_get_gid(p)))
				goto err_param;
		}else if(strcmp("logfile", buf) == 0){
			mc_startup->s_logfile = mc_strdup(p);
		}else if(strcmp("maxprocesses", buf) == 0){
			mc_startup->s_schd.maxproc = atoi(p);
		}else if(strcmp("maxrequests", buf) == 0){ 
			mc_startup->s_schd.maxfds = atoi(p);
		}else if(strcmp("upperthreshold", buf) == 0){
			mc_startup->s_schd.thresholdfds_u = atoi(p);
		}else if(strcmp("lowerthreshold", buf) == 0){
			mc_startup->s_schd.thresholdfds_l = atoi(p);
		}else if(strcmp("processcreat", buf) == 0){
			mc_startup->s_schd.procs = atoi(p);
		}else if(strcmp("cycletime", buf) == 0){
			mc_startup->s_cycle = atoi(p);
		}else{
err_param:
			fclose(fp);
        		mc_warn("Error %u: illegal configuration parameter '%s'\n", getpid(), buf);
        		return -1;
		}
	}	
	fclose(fp);
	return 0;
}

mc_startup_set
mc_deal_configuration(int argc, char *argv[])
{
	if((mc_startup = mc_init_startup()) == NULL){
		mc_warn("Error %u: failed to init startup parameter: %s\n", getpid(), strerror(errno));
		return NULL;
	}
	if(!mc_restart && mc_deal_arg(argc, argv) == -1){
		usage();
		mc_free_startup();
		return NULL;
	}
	if(mc_deal_conffile() == -1){
		mc_free_startup();
		return NULL;
	}
	return mc_startup;
}
