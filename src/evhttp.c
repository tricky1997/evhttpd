#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/time.h>
#include <arpa/inet.h>


#include "evhttp.h"
#include "http.h"
#include "evsignal.h"

#define DIE(mesg) log_error_mesg(__FILE__, __LINE__, mesg), exit(1)


static struct setting {
	const char *server_root;
	const char *bind_if;
	const char *def_index;
	const char *err_log;

	unsigned int uid;
	unsigned short conn_timeout_sec;
	unsigned short server_port;
	unsigned short nthreads;
	unsigned int backlog;
} server_setting;

struct worker {
	pthread_t tid;

	struct request *waiting_requests;
	pthread_mutex_t requests_mutex;

	int notify_fds[2];
	struct event_base *base;

	struct {
		unsigned long areqs;
		unsigned long sreqs;
		unsigned long freqs;
	} log;
};

struct main_worker mainworker;
static struct worker *workers;

static pthread_mutex_t free_events_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct event *free_events;
#define NFREE_EVENTS 16


static pthread_mutex_t free_requests_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct request *free_requests;
#define NFREE_REQUESTS 16

static struct timeval conn_timeout= {
	.tv_sec = 0,
	.tv_usec = 0
};

static void log_error_mesg(char *file, int line, char *mesg)
{
    int errno_save = errno;
    fprintf(stderr, "%s:%d - ", file, line);
    errno = errno_save;
    perror(mesg);
    errno = errno_save;
}

static int set_nonblock(int fd)
{
	long flags;
	if ((flags = fcntl(fd, F_GETFL, NULL)) == -1) {
		fprintf(stderr, "fcntl F_GETFL err");
		return -1;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		fprintf(stderr, "fcntl F_SETFL err");
		return -1;
	}
	return 0;
}

static void init_setting()
{
	if (!server_setting.server_root)
		server_setting.server_root = "/home/worker/WWW"; 
	if (!server_setting.server_port)
		server_setting.server_port = 9999; 

	if (!server_setting.def_index)
		server_setting.def_index = "/index.html";

	if (!server_setting.nthreads)
		server_setting.nthreads = 8;

	if (!server_setting.conn_timeout_sec)
		server_setting.conn_timeout_sec = 60; 

	conn_timeout.tv_sec = server_setting.conn_timeout_sec;

	if (!server_setting.backlog) {
		/* we don't check if backlog is too large, 
		 * in case admin hacked the kernel. 
		 * we only set default to 5.
		 */
		server_setting.backlog = 5;
	}
	return;
}

/*
static struct setting {
	char *server_root;
	unsigned short server_port;
	char *bind_if;
	int uid;
	char *def_index;
	char *log_file;
} server_setting;
*/

static int create_server_fd()
{
	int flags = 1;
	int ret = 0;
	int sfd = 0;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_setting.server_port);
	if (server_setting.bind_if && (inet_aton(server_setting.bind_if, &addr.sin_addr) != -1))
		;
	else 
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sfd = socket(AF_INET, SOCK_STREAM, 0);

	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
        
	ret = setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
	if (ret != 0) {
		
		perror("setsockopt");
	}

	ret = bind(sfd, (const struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0)
		DIE("bind");

	ret = listen(sfd, server_setting.backlog);
	if (ret != 0)
		DIE("listen");

	return sfd;
}

static void init_log()
{
	fclose(stdin);

	if (server_setting.err_log) {
		fclose(stderr);
		stderr = fopen(server_setting.err_log, "w");
	}

	if (!stderr) {
		printf("open err log: %s", strerror(errno));
		exit(1);
	}

	fclose(stdout);
	return;
}

#if 0
static int reserve_waiting_requests(struct worker *w, size_t n)
{
	int a = w->awaiting_requests;

	if (!w)
		return -1;

	if (n < a)
		return 0;

	a = a ? a * a : 8 ;
	if (!realloc(w->waiting_requests, a)) {		
		return -1;
	}
	return 0;
}
#endif

static struct event * get_free_event()
{
	int i;
	struct event *ret;

	pthread_mutex_lock(&free_events_mutex);
	if (!free_events) {

		free_events = calloc(NFREE_EVENTS, event_get_struct_event_size());
		if (!free_events) {
			pthread_mutex_unlock(&free_events_mutex);
			return NULL;
		}
		
		for (i = 0; i < NFREE_EVENTS - 1; ++i ) {
			free_events[i].ev_next.tqe_next = &free_events[i+1];
		}
		free_events[i].ev_next.tqe_next = NULL;	       
	}

	ret = free_events;
	free_events = free_events->ev_next.tqe_next;
	pthread_mutex_unlock(&free_events_mutex);

	return ret;
}

static int put_free_event(struct event *e)
{
	if (!e)
		return -1;

	pthread_mutex_lock(&free_events_mutex);

	e->ev_next.tqe_next = free_events;
	free_events = e;

	pthread_mutex_unlock(&free_events_mutex);
	return 0;
}

static void free_request(struct request *req)
{
	if (!req)
		return;
	
	free(req->in_http);
	req->in_http = NULL;

	
	if (O_INFO(req).fd)
		close(O_INFO(req).fd);

	if (req->connfd)
		close(req->connfd);

	memset(req, 0, sizeof(*req));
}

static struct request * get_free_request()
{
	int i;
	struct request *ret;
	
	pthread_mutex_lock(&free_requests_mutex);
	if (!free_requests) {

		free_requests = calloc(NFREE_REQUESTS, sizeof(*free_requests));
		if (!free_requests) {
			pthread_mutex_unlock(&free_requests_mutex);
			return NULL;
		}
		
		for (i = 0; i < NFREE_REQUESTS - 1; ++i ) {
			free_requests[i].next = &free_requests[i+1];
		}
		free_requests[i].next = NULL;
	}

	ret = free_requests;
	free_requests = free_requests->next;
	pthread_mutex_unlock(&free_requests_mutex);

	return ret;
}

static int put_free_request(struct request *req)
{
	if (!req)
		return -1;

	free_request(req);

	pthread_mutex_lock(&free_requests_mutex);
	req->next = free_requests;
	free_requests = req;
	pthread_mutex_unlock(&free_requests_mutex);

	return 0;
}


static void conn_read_cb(evutil_socket_t fd, short what, void *arg)
{
#define	buf_len 4096

	char buf[buf_len];
	struct request *req = (struct request*)arg;
	struct event *e = req->ev;
	
	int n;
	int more = 1;

	if (what & EV_TIMEOUT)
		goto free_conn;

	if (!req)
		DIE("conn_read_cb null request");

	while (more) {
		more = 0;
		n = recv(fd, buf, buf_len, 0);
		switch (n) {
		case -1:
			if (errno == EAGAIN || EWOULDBLOCK)
				return;
			fprintf(stderr, "recv %d err: %s\n", fd, strerror(errno));
			break;
		case 0:
			goto free_conn;
			break;
		case buf_len:
			more = 1;
			
		default:
			req->in_http_len += n;
			req->in_http = realloc(req->in_http, req->in_http_len + 1);
			if (req->in_http == NULL) {
				fprintf(stderr, "conn_read_cb: realloc\n");
				goto free_conn;
			}
			
			if (req->in_http_len == n)
				req->in_http[0] = 0;
			strncat(req->in_http, buf, n);
			req->in_http[req->in_http_len] = 0;
			break;
		}
	}

	switch (do_request(req)) {
	case -1: goto free_conn;
	case 0:	
		/* XXX not support keep-alive now
		 * if we finish a request, we send FIN, and wait read 0
		 */
#if 0
		if (shutdown(fd, SHUT_WR) == -1)
			goto free_conn;
#endif		
		goto free_conn;
		break;
	case 1: return;
	}
	return;

free_conn:
	event_del(e);
	put_free_event(e);
	put_free_request(req);
	return;
#undef buf_len
}

static void notify_cb(evutil_socket_t fd, short what, void *arg)
{
	int n;
	int buf[1024];
	struct worker *w = arg;
	struct request *req;
	struct event *e;

	n = read(w->notify_fds[0], buf, sizeof(buf));
	if (n == -1) {
		fprintf(stderr, "read from pipe err %s\n", strerror(errno));
	}

	while (1) {
		pthread_mutex_lock(&w->requests_mutex);	
		req = w->waiting_requests;
		if (!req) {
			pthread_mutex_unlock(&w->requests_mutex);
			break;
		}
		w->waiting_requests = req->next;
		pthread_mutex_unlock(&w->requests_mutex);
		
		e = get_free_event();
		if (!e) {
			put_free_request(req);
		}

		req->ev = e;
		if (event_assign(e, w->base, req->connfd, EV_READ | EV_PERSIST, conn_read_cb, (void*)req) == -1 || (event_add(e, &conn_timeout) == -1)) {
			put_free_request(req);
			put_free_event(e);
		}

	}
	return;
}

static void init_worker(struct worker *w)
{
	struct event *e;

	memset(w, 0, sizeof(*w));

	if (pipe(w->notify_fds) == -1)
		DIE("pipe");
	if (set_nonblock(w->notify_fds[0]) == -1 || set_nonblock(w->notify_fds[1] == -1))
		DIE("set_nonblock");

	w->base = event_base_new();
	if (!w->base)
		DIE("event_base_new");

	e = get_free_event();
	if (!e)
		DIE("get_free_event");

	if (event_assign(e, w->base, w->notify_fds[0], EV_READ | EV_PERSIST, &notify_cb, w) == -1)
		DIE("event_assign");

	if (event_add(e, NULL) == -1)
		DIE("event_add");

	if (pthread_mutex_init(&w->requests_mutex, NULL) == -1)
		DIE("init requests_mutex");

	return ;
}

static void* worker_thread(void *a)
{
	struct worker *w = (struct worker*)a;

	pthread_sigmask(SIG_BLOCK, &sigmask, NULL);

	pthread_mutex_unlock(&w->requests_mutex);
	
	event_base_loop(w->base, 0);
	
	pthread_exit(0);
}

static void init_workers(int n)
{
	int i;

	if (!n)
		DIE("init 0 workers");

	workers = calloc(n, sizeof(*workers));
	if (!workers) {
		DIE("calloc");
	}
	
	for (i = 0; i < n; ++i) {
		init_worker(&workers[i]);
		pthread_mutex_lock(&workers[i].requests_mutex);
		pthread_create(&workers[i].tid, NULL, worker_thread, &workers[i]);
	}
	return;
}

static void put_waiting_request(struct worker *w, struct request *req)
{
	if (!w || !req)
		return;

	pthread_mutex_lock(&w->requests_mutex);
	req->next = w->waiting_requests;
	w->waiting_requests = req;
	pthread_mutex_unlock(&w->requests_mutex);
}

static void accept_cb(evutil_socket_t fd, short what, void *arg)
{
	struct sockaddr_in addr;
	struct request *req;
	int addr_len = 0;
	int nfd = 0;
	

	memset(&addr, 0, sizeof(addr));
	nfd = accept(fd, (struct sockaddr *)&addr, (socklen_t *)&addr_len);
	if (nfd == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		DIE("accept");
	}

	
	

	if (set_nonblock(nfd) == -1) {
		fprintf(stderr, "set_nonblock\n");
		close(nfd);
		return;
	}

	req = get_free_request();
	if (!req) {
		fprintf(stderr, "get_free_request\n");
		close(nfd);
		return;
	}

	memset(req, 0, sizeof(*req));
	req->connfd = nfd;
	req->addr = addr;

	
	if (++mainworker.lworker >= mainworker.nworkers)
		mainworker.lworker = 0;

	put_waiting_request(&workers[mainworker.lworker], req);
	workers[mainworker.lworker].log.areqs++;
	if (write(workers[mainworker.lworker].notify_fds[1], "", 1) == -1)
		fprintf(stderr, "workers[%d]'s pipe 1 is broken\n", mainworker.lworker);

	return;
}

static void init_mainworker()
{
	struct event *e;
	int ret;
	unsigned int i;

	mainworker.sig_hup = mainworker.sig_term = 0;
	init_signals();

	mainworker.nworkers = server_setting.nthreads;
	mainworker.lworker = 0;

	ret = create_server_fd();
	if (ret == -1) {
		DIE("create server socket error!");
	}
	mainworker.listen_fd = ret;

	mainworker.base = event_base_new();
	if (!mainworker.base) {
		DIE("event_base_new");
	}

	e = get_free_event();
	if (!e)
		DIE("get_free_event");
	if (event_assign(e, mainworker.base, mainworker.listen_fd, EV_READ | EV_PERSIST, &accept_cb, 0) == -1)
		DIE("event_assign");

	if (event_add(e, NULL) == -1)
		DIE("event_add");

	/* check all lock to see if threads init OK
	 * busy wait and race condition may be improved
	 */
	for (i = 0 ; i < mainworker.nworkers; ) {
		if (!pthread_mutex_trylock(&workers[i].requests_mutex)) {
			
			pthread_mutex_unlock(&workers[i].requests_mutex);
			++i;
		}
		
	}

	event_base_loop(mainworker.base, 0);
	return;
}

static void init_globals()
{
	free_requests = NULL;
	free_events = NULL;
}

static void daemonize()
{
/*
	switch(fork()) {
	case -1:
		DIE("fork");
		break;
	case 0:
		setsid();
		break;
	default:
		_exit(0);
		break;
	}
*/
	return;
}

static void changerootto(const char* path)
{
	if (!path)
		DIE("path NULL");

	if (chdir(path) == -1)
                DIE("chdir (to chroot)");
	
	if (chroot(path) == -1)
		DIE("chroot");

	if (chdir("/") == -1)
		DIE("chdir (after chroot");

	return;
}

int main(void)
{
	int i;
	init_setting();
	init_globals();

	daemonize();

	changerootto(server_setting.server_root);
	init_log();

	init_workers(server_setting.nthreads);
	init_mainworker();
	
	for ( i = 0 ; i < mainworker.nworkers; ++i) {
		warnx("worker%d: %d areqs", i, workers[i].log.areqs);
	}

	exit(0);
}
