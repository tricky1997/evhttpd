#ifndef _HTTP_H_
#define _HTTP_H_
#include <netinet/in.h>
#include "http_parser.h"

#define I_INFO(r)				\
	((struct request*)r)->in_http_info
#define O_INFO(r)				\
	((struct request*)r)->out_http_info

#define setstatus(r, s)							\
	do {								\
	(r)->out_http_info.status_code = http_status_map[(s)].status_code; \
	(r)->out_http_info.status_description = http_status_map[(s)].status_description; \
	}while(0)

#ifndef DEBUG
#define seterrstatus(r, s)			\
	do{					\
		(r)->in_http_err = 1;		\
		setstatus((r), (http_err_ind=(s)));	\
	}while(0)
#else
#define seterrstatus(r, s) set_err_status(r, s)
#endif


#define MAX_HEADERS 20
#define MAX_URL_SIZE 512
#define MAX_ELEMENT_SIZE 128
#define MAX_BODY_SIZE 1024

struct http_status {
	short status_code;
	const char* status_description;
};

struct in_http_info {
	enum http_parser_type type;
	enum http_method method;
	int status_code;
	char request_path[MAX_ELEMENT_SIZE];
	size_t request_path_len;
	char request_url[MAX_URL_SIZE];
	size_t request_url_len;
	char fragment[MAX_ELEMENT_SIZE];
	size_t fragment_len;
	char query_string[MAX_ELEMENT_SIZE];
	size_t query_string_len;
	char body[MAX_BODY_SIZE];
	size_t body_len;
	uint16_t port;
	int num_headers;
	enum { NONE=0, FIELD, VALUE } last_header_element;
	struct {
		size_t f_len;
		size_t v_len;
		char f[MAX_ELEMENT_SIZE];
		char v[MAX_ELEMENT_SIZE];
	} headers[MAX_HEADERS];
	int should_keep_alive;

	unsigned short http_major;
	unsigned short http_minor;

	int message_begin_cb_called;
	int headers_complete_cb_called;
	int message_complete_cb_called;
	int message_complete_on_eof;
};

#define MAX_SERVER_ROOT_SIZE 32
#define MAX_FD_PATH_SIZE MAX_ELEMENT_SIZE+MAX_SERVER_ROOT_SIZE
struct out_http_info {
	int fd;
	
	off_t fd_off;
	off_t fd_size;
	short status_code;
	const char* status_description;
};

struct event;
struct request {
	struct sockaddr_in addr;
	int connfd;
	struct event *ev;

	char *in_http;
	size_t in_http_len;
	int in_http_cur;
	int in_http_err;
	int parser_inited;
	http_parser parser;
	struct in_http_info in_http_info;
	
	struct out_http_info out_http_info;

	struct request *next;
};	
/*
int parse_request(struct request*);
int prepare_response(struct request*);
*/
int do_request(struct request*);

#endif
