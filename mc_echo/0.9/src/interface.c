#include	"server.h"

FILE	*mc_stdin;
FILE	*mc_stdout;
FILE	*mc_stderr;

int
mc_lock(void)
{
retry:
	if(sem_wait(mc_startup->s_lock.key) == -1 && errno == EINTR)
		goto retry;
	mc_startup->s_lock.pid = getpid();
}

int
mc_unlock(void)
{
	mc_startup->s_lock.pid = 0;
	sem_post(mc_startup->s_lock.key);
}

void
mc_warn(const char *fmt, ...)
{
	va_list	ap;

	mc_print_time();
	va_start(ap, fmt);
	vfprintf(mc_stderr ? mc_stderr : stderr, fmt, ap);
	va_end(ap);
}

void
mc_err(const char *fmt, ...)
{
	va_list	ap;

	mc_print_time();
	va_start(ap, fmt);
	vfprintf(mc_stderr ? mc_stderr : stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

uid_t	
mc_get_uid(const char *user)
{
	struct passwd	*up;

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
	struct group	*gp;

	if(group == NULL)
		return 0;
	if(gp = mc_getgrnam(group)){
		return gp->gr_gid;
	}else if(gp = mc_getgrgid(atoi(group)))
		return gp->gr_gid;
	return 0;
}

void
mc_print_time(void)
{
	time_t	t;

	if((t = time(NULL)) != -1)
		fprintf(mc_stderr ? mc_stderr : stderr, "--------------------------------\n%s", asctime(gmtime(&t)));
}

void	*
mc_memcpy(void *dst, const void *src, size_t n) 
{
#if MC_HAVE_MEM_STRING
	return memcpy(dst, src, n);	
#elif MC_HAVE_BSD_STRING
	return bcopy(src, dst, n);
#else
	return strncpy(dst, src, n);
#endif
}

void	*
mc_memset(void *s, int c, size_t n)
{
#if MC_HAVE_MEM_STRING
	return memset(s, c, n);
#else
	size_t t;
        unsigned int    x;
        unsigned char   *p;

        p = s;
        if(n < 3 * SIZEOF_UNSIGNED_INT){
                do{
                        *p++ = c;
                }while(--n > 0);
        }
        if((x = (unsigned char)c) != 0){
                x = (x << 8) | x;
                if(SIZEOF_UNSIGNED_INT > 2)
                        x = (x << 16) | x;
                if(SIZEOF_UNSIGNED_INT > 4)
                        x = (x << 32) | x;
        }
        if((t = (long)p & (SIZEOF_UNSIGNED_INT - 1)) != 0){
                t = SIZEOF_UNSIGNED_INT - t;
                n -= t;
                do{
                        *p++ = c;
                }while(--t > 0);
        }
        for(t = n / SIZEOF_UNSIGNED_INT; t > 0; t--, p += SIZEOF_UNSIGNED_INT)
                *(unsigned int *)p = x;
        if((t = n & (SIZEOF_UNSIGNED_INT - 1)) != 0){
                do{
                        *p++ = c;
                }while(--t > 0);
        }
        return s;
#endif
}

void	*
mc_memchr(const void *s, int c, size_t n)
{
#if MC_HAVE_MEM_STRING
	return memchr(s, c, n);	
#else 
	if(n != 0){
		const unsigned char *p = s;

		do{
			if(*p++ == (unsigned char)c)
				return ((void *)(p - 1));
		}while(--n != 0);
	}
	return NULL;
#endif
}

char	*
mc_strchr(const char *s, int c)
{
#if MC_HAVE_STR_STRING
	return strchr(s, c);
#elif MC_HAVE_BSD_STRING
	return index(s, c);
#else
	const unsigned char	*p;

	for(p = s; *p != '\0'; p++)
		if(*p == (unsigned char)c)
			return (void *)p; 
	return NULL;
#endif
}

char	*
mc_strrchr(const char *s, int c)
{
#if MC_HAVE_STR_STRING
	return strchr(s, c);
#elif MC_HAVE_BSD_STRING
	return rindex(s, c);
#else
	const unsigned char	*p, *q;	
	
	q = NULL;
	for(p = s; *p != '\0'; p++)
		if(*p == (unsigned char)c)
			q = p;	
	return q;
#endif
}

char	*
mc_strdup(const char *s)
{
	if(s == NULL)
		return NULL;
#if HAVE_STRDUP
	return strdup(s);
#else
	char	*p;
	size_t 	len;

	len = strlen(s) + 1;
	if((p = malloc(len * sizeof(char))) == NULL)		
		return NULL;
	mc_memcpy(p, s, len);		
	return	p;
#endif
}

char	*
mc_strndup(const char *s, size_t n)
{
#if HAVE_STRDUP
	return strndup(s, n);
#else 
	char	*p;
	
	if((p = malloc((n + 1) * sizeof(char))) == NULL)
		return NULL;
	p[n] = '\0';
	mc_memcpy(p, s, n);
	return p;
#endif
}

size_t
mc_strspn(const char *s1, const char *s2)
{
#if MC_HAVE_STR_STRING
	return strspn(s1, s2);
#else
	const char *p = s1, *spanp;
	char c, sc;

cont:
	c = *p++;
	for (spanp = s2; (sc = *spanp++) != 0;)
		if (sc == c)
			goto cont;
	return (p - 1 - s1);	
#endif
}

size_t
mc_strcspn(const char *s1, const char *s2)
{
#if MC_HAVE_STR_STRING
	return strcspn(s1, s2);
#else
	const char *p, *spanp;
	char c, sc;

	for (p = s1;;) {
		c = *p++;
		spanp = s2;
		do {
			if ((sc = *spanp++) == c)
				return (p - 1 - s1);
		} while (sc != 0);
	}
#endif
}

char	*
mc_strpbrk(const char *s1, const char *s2)
{
#if MC_HAVE_STR_STRING
	return strpbrk(s1, s2);
#else
	int	x, y;
	const char	*p;

	while((x = *s1++)){
		for(p = s2; y = *s2; s2++){
			if(x == y)
				return (char *)(s1 - 1); 
		}
	}
	return NULL;
#endif
}
	
char	*
mc_strstr(const char *s1, const char *s2)
{
#if MC_HAVE_STR_STRING
	return strstr(s1, s2);	
#else
	size_t	len;
	char	x, y;

	if((x = *s2++) != '\0'){
		len = strlen(s2);
		do{
			do{
				if((y = *s1++) == '\0')
					return NULL;
			}while(x != y);
		}while(mc_memcmp(s1, s2, len) != 0);
		s1--;
	}
	return s1;
#endif
}

int
mc_memcmp(const void *s1, const void *s2, size_t n)
{
#if MC_HAVE_MEM_STRING
	return memcmp(s1, s2, n);
#elif MC_HAVE_BSD_STRING
	return bcmp(s1, s2, n);
#else
	if(n != 0){
		const unsigned char 	*p1 = s1, *p2 = s2;

		do{
			if(*p1++ != *p2++)
				return (*--p1 - *--p2);
		}while(--n != 0);
	}	
	return 0;
#endif
}

mc_event
mc_init_event(int maxfds)
{
	mc_event	p;

	if((p = malloc(MC_EVENT_SIZE)) == NULL)
		return NULL;
	p->nfds = 0;
	p->maxfds = maxfds;
#ifdef MC_USE_KQUEUE
	if((p->fd = kqueue()) == -1){
		free(p);
		return NULL;
	}
	if((p->fds = malloc(p->maxfds * sizeof(struct kevent))) == NULL){
		close(p->fd);
		free(p);
		return NULL;
	}
	p->add = mc_event_kqueue_add;
	p->del = mc_event_kqueue_del;
	p->free = mc_event_kqueue_free;
	p->poll = mc_event_kqueue_poll;
	p->traverse = mc_event_kqueue_traverse;
#endif
#ifdef MC_USE_EPOLL
	if((p->fd = epoll_create(p->maxfds)) == -1){
		free(p);
		return NULL;
	} 
	if((p->fds = malloc(p->maxfds * sizeof(struct epoll_event))) == NULL){
		close(p->fd);
		free(p);
		return NULL;
	}
	p->add = mc_event_epoll_add;
	p->del = mc_event_epoll_del;
	p->free = mc_event_epoll_free;
	p->poll = mc_event_epoll_poll;
	p->traverse = mc_event_epoll_traverse;
#endif
#ifdef MC_USE_DEVPOLL
	if((p->fd = mc_open("/dev/poll", O_RDWR)) == -1){
		free(p);
		return NULL;
	}
	if((p->fds = malloc(p->maxfds * sizeof(struct pollfd))) == NULL){
		close(p->fd);
		free(p);
		return NULL;
	}
	p->add = mc_event_devpoll_add;
	p->del = mc_event_devpoll_del;
	p->free = mc_event_devpoll_free;
	p->poll = mc_event_devpoll_poll;
	p->traverse = mc_event_devpoll_traverse;
#endif
#ifdef MC_USE_POLL
	if((p->fds = malloc(p->maxfds * sizeof(struct pollfd))) == NULL){
		free(p);
		return NULL;
	}
	p->add = mc_event_poll_add;
	p->del = mc_event_poll_del;
	p->free = mc_event_poll_free;
	p->poll = mc_event_poll_poll;
	p->traverse = mc_event_poll_traverse;
#endif
	return p;
}
	
#if MC_USE_DEVPOLL
int
mc_event_devpoll_free(mc_event p)
{
        mc_close(p->fd);
        free(p->fds);
        free(p);
        return 0;
}

int
mc_event_devpoll_poll(mc_event p, int timeout)
{
	int	n;
	struct dvpoll	event;	
	
	event.dp_fds = evp->fds;			
	event.dp_nfds = evp->nfds;
	event.dp_timeout = timeout;

retry:
	if((n = ioctl(p->fd, DP_POLL, &event)) == -1 && errno == EINTR)
		goto retry;
	p->offset = 0;
	return (p->events = n);
}

int
mc_event_devpoll_add(mc_event p, int fd, int flags)
{
	struct pollfd	event;

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	mc_memset(&event, 0, sizeof(event));
	event.fd = fd;
	if(flags & MC_EVENT_IN)
		event.events |= POLLIN;
	if(flags & MC_EVENT_OUT)
		event.events |= POLLOUT;
	if(mc_write(p->fd, &event, sizeof(event)) == -1)
		return -1;
	p->nfds++;
	return 0;
}
 
int
mc_event_devpoll_del(mc_event p, int fd, int flags)
{
	struct pollfd	event;

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	mc_memset(&event, 0, sizeof(event));
	event.fd = fd;
	event.events = POLLREMOVE;	
	if(mc_write(p->fd, &event, sizeof(event)) == -1)
		return -1;
	p->nfds--;
	return 0;
}

int
mc_event_devpoll_traverse(mc_event p, mc_pollfd pollp)
{
	struct pollfd	tm;
	struct pollfd	*pp;

        while(p->offset < p->events){
                pp = &p->fds[p->offset++];
                pollp->fd = pp->fd;
		tm.fd = pp->fd;
		tm.events = tm.revents = 0;
retry:
		switch(ioctl(p->fd, DP_ISPOLLED, &tm)){
		case -1:
			if(errno == EINTR)
				got retry;
			continue; 
		case 1: 
			if(tm.revents & (POLLHUP | POLLERR)){
                        	pollp->revents = MC_EVENT_ERR;
                	}else if(tm.revents & POLLIN){
                        	pollp->revents = MC_EVENT_IN;
                	}else if(tm.revents & POLLOUT)
                        	pollp->revents = MC_EVENT_OUT;
			return 0;	
		default: 
			continue;
		}
        }
        return -1;
}
#endif

#if MC_USE_EPOLL
int
mc_event_epoll_free(mc_event p)
{
        mc_close(p->fd);
        free(p->fds);
        free(p);
        return 0;
}

int
mc_event_epoll_poll(mc_event p, int timeout)
{
	int	n;

retry:
	if((n = epoll_wait(p->fd, p->fds, p->nfds, timeout)) == -1 && errno == EINTR)
		goto retry;
	p->offset = 0;
	return (p->events = n);
}

int
mc_event_epoll_add(mc_event p, int fd, int flags)
{
	struct epoll_event	event;	

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	mc_memset(&event, 0, sizeof(event));
	event.events = EPOLLET;
	if(flags & MC_EVENT_IN)
		event.events |= EPOLLIN;	
	if(flags & MC_EVENT_OUT)
		event.events |= EPOLLOUT;
	event.data.fd = fd;
	if(epoll_ctl(p->fd, EPOLL_CTL_ADD, fd, &event) == 0){
		p->nfds++;
		return 0;
	}
	return -1;
}

int
mc_event_epoll_del(mc_event p, int fd, int flags)
{
	struct epoll_event	event;

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	mc_memset(&event, 0, sizeof(event));
	event.events = EPOLLET;
	if(flags & MC_EVENT_IN)
		event.events |= EPOLLIN;
	if(flags & MC_EVENT_OUT)
		event.events |= EPOLLOUT;
	event.data.fd = fd;
	if((epoll_ctl(p->fd, EPOLL_CTL_DEL, fd, &event)) == 0){
		p->nfds--;
		return 0;
	}
	return -1;
}

int
mc_event_epoll_traverse(mc_event p, mc_pollfd pollp)
{
	struct epoll_event	*ep;

	if(p->offset < p->events){
                ep = &p->fds[p->offset++];
		pollp->fd = ep->data.fd;
                if(ep->events & (EPOLLHUP | EPOLLERR)){
                        pollp->revents = MC_EVENT_ERR;
                }else if(ep->events & EPOLLIN){
                        pollp->revents = MC_EVENT_IN;
                }else if(ep->events & EPOLLOUT)
                        pollp->revents = MC_EVENT_OUT;
                return 0;
        }
	return -1;
}
#endif

#if MC_USE_KQUEUE
int
mc_event_kqueue_free(mc_event p)
{
	mc_close(p->fd);
	free(p->fds);
       	free(p);
	return 0;
}

int
mc_event_kqueue_poll(mc_event p, int timeout)
{
	int	n;
	struct timespec	t;	

	if(timeout >= 0){
		t.tv_sec = timeout / 1000;	
		t.tv_nsec = (timeout  % 1000) * 1000000;
	}
retry:
	if((n = kevent(p->fd, NULL, 0, p->fds, p->nfds, timeout >= 0 ? &t : NULL)) == -1 && errno == EINTR)
		goto retry;
	p->offset = 0;
	return (p->events = n);
}

int
mc_event_kqueue_add(mc_event p, int fd, int flags) 
{
	int	n;
	struct timespec ts;
	struct kevent	tm[2];

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	n = 0;
	if(flags & MC_EVENT_IN) 
		EV_SET(&tm[n++], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	if(flags & MC_EVENT_OUT)
		EV_SET(&tm[n++], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
	ts.tv_sec = ts.tv_nsec = 0;
	if(kevent(p->fd, tm, n, NULL, 0, &ts) == 0){
		p->nfds++;
		return 0;
	}
	return -1; 
}

int
mc_event_kqueue_del(mc_event p, int fd, int flags)
{
	int	n;
	struct timespec	ts;
	struct kevent	tm[2];

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	n = 0;
	if(flags & MC_EVENT_IN)
		EV_SET(&tm[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if(flags & MC_EVENT_OUT)
		EV_SET(&tm[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	ts.tv_sec = ts.tv_nsec = 0;
	if(kevent(p->fd, &tm, n, NULL, 0, &ts) == 0){
		p->nfds--;
		return 0;
	}
	return -1;
}

int
mc_event_kqueue_traverse(mc_event p, mc_pollfd pollp)
{
	struct kevent	*kp;

	if(p->offset < p->events){
		kp = &p->fds[p->offset];
		pollp->fd = kp->ident;
		if(kp->flags & EV_ERROR){
			pollp->revents = MC_EVENT_ERR;
		}else if(kp->filter & EVFILT_READ){
			pollp->revents = MC_EVENT_IN;
		}else if(kp->filter & EVFILT_WRITE)
			pollp->revents = MC_EVENT_OUT;
		return 0;
	}
	return -1;
}
#endif

#if MC_USE_POLL
int
mc_event_poll_free(mc_event p)
{
        free(p->fds);
        free(p);
        return 0;
}

int
mc_event_poll_poll(mc_event p, int timeout)
{
	int	n;

retry:
	if((n = poll(p->fds, p->nfds, timeout)) == -1 && errno == EINTR)
		goto retry; 
	p->offset = 0;
	return (p->events = n);
}

int
mc_event_poll_add(mc_event p, int fd, int flags)
{
	int	i;
	struct pollfd 	*pp;

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	pp = &p->fds[p->nfds++];
	if(flags & MC_EVENT_IN)
		pp->events |= POLLIN;
	if(flags & MC_EVENT_OUT)
		pp->events |= POLLOUT;
	pp->fd = fd;
	pp->revents = 0;
	return 0;
}

int
mc_event_poll_del(mc_event p, int fd, int flags)
{
	int	i;

	if(fd < 0 || fd >= p->maxfds)
		return -1;
	for(i = 0; i < p->nfds && p->fds[i].fd != fd; i++)
		;
	if(i == p->nfds)
		return -1;
	--p->nfds;
	if(i < p->nfds)
		memmove(&p->fds[i], &p->fds[i + 1], p->nfds - i);	
	return 0;
}

int
mc_event_poll_traverse(mc_event p, mc_pollfd pollp)
{
	int	i;

	for(i = p->offset; p->events > 0 && i < p->nfds; i++){
		if(!p->fds[i].revents)
			continue;
		pollp->fd = p->fds[i].fd;
		if(p->fds[i].revents & (POLLERR | POLLHUP)){
			pollp->revents = MC_EVENT_ERR;
		}else if(p->fds[i].revents & POLLIN){
			pollp->revents = MC_EVENT_IN;
		}else if(p->fds[i].revents & POLLOUT)
			pollp->revents = MC_EVENT_OUT;
		p->events--;
		p->offset = i + 1;
		p->fds[i].revents = 0;
		return 0;
	}	
        return -1;
}
#endif
