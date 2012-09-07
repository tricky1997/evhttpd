#ifndef _EVHTTP_H_
#define _EVHTTP_H_


struct event_base;
struct main_worker {
	unsigned int sig_term : 1;
	unsigned int sig_hup : 1;
	unsigned int nworkers;
	unsigned int lworker;
	int listen_fd;
	struct event_base *base;
};

extern struct main_worker mainworker;
#endif
