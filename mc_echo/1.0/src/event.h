#ifndef _MC_EVENT_H
#define _MC_EVENT_H

#include	"mc.h"

#if 0
#if (HAVE_KQUEUE && HAVE_SYS_EVENT_H)
#define MC_USE_KQUEUE	1
#include	<sys/event.h>
#elif (HAVE_EPOLL_CTL && HAVE_SYS_EPOLL_H)
#define MC_USE_EPOLL	1	
#include	<sys/epoll.h>
#elif (HAVE_SYS_DEVPOLL_H && defined (__sun))
#define MC_USE_DEVPOLL	1	
#include	<sys/devpoll.h>
#elif (HAVE_POLL && (HAVE_SYS_POLL_H || POLL_H))
#define MC_USE_POLL	1	
#else
#define MC_NONE_IO	1
#endif 
#endif

#define MC_USE_POLL 	1

#if HAVE_POLL_H
#include	<poll.h>
#else
#include	<sys/poll.h>
#endif

#ifndef MC_EVENT_IN
#define MC_EVENT_IN	1	
#endif

#ifndef MC_EVENT_OUT
#define MC_EVENT_OUT	2	
#endif

#ifndef MC_EVENT_ERR
#define MC_EVENT_ERR	4	
#endif

#define MC_POLLFD_SIZE	(sizeof(struct mc_pollfd))
typedef struct mc_pollfd	*mc_pollfd;
struct mc_pollfd{ 
	int	fd;
	short	revents;	
};

#define MC_EVENT_SIZE	(sizeof(struct mc_event))
typedef struct mc_event	*mc_event;
struct mc_event{
	int	nfds;	
	int	maxfds;	
	int	offset, events; 
	SSL	*ssl;
#ifdef	MC_USE_KQUEUE
	int	fd;
	struct kevent	*fds;
#endif
#ifdef MC_USE_EPOLL
	int	fd;	
	struct epoll_event	*fds;
#endif
#ifdef MC_USE_DEVPOLL
	int	fd;
	struct pollfd 	*fds;
#endif
#ifdef 	MC_USE_POLL
	struct	pollfd	*fds; 
#endif
	int	(*free)(mc_event evp);
	int	(*poll)(mc_event evp, int timeout);	
	int	(*add)(mc_event evp, int fd, int flags); 
	int	(*del)(mc_event evp, int fd, int flags);		
	int	(*traverse)(mc_event evp, mc_pollfd pollp);		
}; 

extern mc_event	mc_evp;

mc_event	mc_init_event(int maxfds);
#if MC_USE_DEVPOLL
int	mc_event_devpoll_free(mc_event p);
int	mc_event_devpoll_poll(mc_event p, int timeout);
int	mc_event_devpoll_add(mc_event p, int fd, int flags);
int	mc_event_devpoll_del(mc_event p, int fd, int flags);
int	mc_event_devpoll_traverse(mc_event p, mc_pollfd pollp);
#endif
#if MC_USE_EPOLL
int	mc_event_epoll_free(mc_event p);
int	mc_event_epoll_poll(mc_event p, int timeout);
int	mc_event_epoll_add(mc_event p, int fd, int flags);
int	mc_event_epoll_del(mc_event p, int fd, int flags);
int	mc_event_epoll_traverse(mc_event p, mc_pollfd pollp);
#endif
#if MC_USE_KQUEUE
int	mc_event_kqueue_free(mc_event p);
int	mc_event_kqueue_poll(mc_event p, int timeout);
int	mc_event_kqueue_add(mc_event p, int fd, int flags);
int	mc_event_kqueue_del(mc_event p, int fd, int flags);
int	mc_event_kqueue_traverse(mc_event p, mc_pollfd pollp);
#endif
#if MC_USE_POLL
int	mc_event_poll_free(mc_event p);
int	mc_event_poll_poll(mc_event p, int timeout);
int	mc_event_poll_add(mc_event p, int fd, int flags);
int	mc_event_poll_del(mc_event p, int fd, int flags);
int	mc_event_poll_traverse(mc_event p, mc_pollfd pollp);
#endif

#endif
