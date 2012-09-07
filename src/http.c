#include <stdio.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "http_parser.h"
#include "http.h"

/* most functions in this file would be used 
 * in multi-thread context. be careful.
 */

enum http_status_type {
	OK = 0,
	BAD_REQUEST,
	NOT_FOUND,
	METHOD_NOT_ALLOWED,
	REQUEST_TIMEOUT,
	REQUEST_ENTITY_TOO_LARGE,
	REQUEST_URI_TOO_LONG,
} http_err_ind;


static const struct http_status http_status_map[] = {
	{200, "OK"},
	{400, "Bad Request"},
	{404, "Not Found"},
	{405, "Method Not Allowed"},
	{408, "Request Timeout"},
	{413, "Request Entity Too Large"},
	{414, "Request Url Too Long"},
};

static const enum http_method supported_methods[] = {
	HTTP_GET,
	HTTP_HEAD,	
};

static pthread_key_t cr_key;
static pthread_once_t cr_once = PTHREAD_ONCE_INIT;
static void cr_destructor(void *ptr)
{
	free(ptr);
	ptr = NULL;
}
static void cr_once_cb(void)
{
	pthread_key_create(&cr_key, cr_destructor);
}
static struct request * get_cur_req()
{
	struct request **crp;
	pthread_once(&cr_once, cr_once_cb);
	if ((crp = pthread_getspecific(cr_key)) == NULL) {
		err(1, "get_cur_req return NULL");
	}
	return *crp;
}

static void set_cur_req(struct request *req)
{
	struct request **crp;
	if (!req)
		return;
	pthread_once(&cr_once, cr_once_cb);
	if ((crp = pthread_getspecific(cr_key)) == NULL) {
		crp = malloc(sizeof(*crp));
		if (crp == NULL)
			err(1, "no memory");
		if (pthread_setspecific(cr_key, crp) == -1)
			
			return;
	}
	*crp = req;
	return;
}

static void set_err_status(struct request *r, enum http_status_type s)
{
	if (!r)
		return;
	r->in_http_err = 1;
	setstatus(r, s);
}

static int check_headers(struct request *req)
{
	int methods_n = sizeof(supported_methods)/sizeof(supported_methods[0]);
	int i = 0;
	int major_minor = 0;
	
	if (!req)
		return -1;

	major_minor = req->in_http_info.http_major * 10 + req->in_http_info.http_minor;

	
	for (i = 0; i <= methods_n; ++i) {
		if (req->in_http_info.method == supported_methods[i])
			break;
	}
	if (i > methods_n) {
		seterrstatus(req, METHOD_NOT_ALLOWED);
		return -1;
	}

	
	if (major_minor != 11 && major_minor != 10) {
		seterrstatus(req, BAD_REQUEST);
		return -1;
	}
	return 0;
}

static int message_begin_cb (http_parser *parser)
{
	struct request *cur_req = get_cur_req();
	struct in_http_info *info = &I_INFO(cur_req);

	if (!parser)
		return -1;
	info->message_begin_cb_called = 1;
	return 0;
}


static int headers_complete_cb (http_parser *parser)
{
	struct http_parser_url u;
	struct request *cur_req = get_cur_req();
	struct in_http_info *info = &I_INFO(cur_req);
	if (!parser)
		return -1;
	info->method = parser->method;
	info->status_code = parser->status_code;
	info->http_major = parser->http_major;
	info->http_minor = parser->http_minor;
	info->headers_complete_cb_called = 1;
	info->should_keep_alive = http_should_keep_alive(parser);

	memset(&u, 0, sizeof(u));
	if (-1 == http_parser_parse_url(info->request_url, info->request_url_len, info->method == HTTP_CONNECT ? 1 : 0, &u)) {
		seterrstatus(cur_req, BAD_REQUEST);
		info->message_complete_cb_called = 1;
		return -1;
	}

	if (u.field_data[UF_PATH].len >= MAX_ELEMENT_SIZE) {
		seterrstatus(cur_req, BAD_REQUEST);
		info->message_complete_cb_called = 1;
		return -1;
	}

	memcpy(info->request_path, info->request_url + u.field_data[UF_PATH].off, u.field_data[UF_PATH].len);

	if (check_headers(cur_req) == -1) {
		info->message_complete_cb_called = 1;
		return -1;
	}

	return 0;
}

static int message_complete_cb (http_parser *parser)
{
	struct request *cur_req = get_cur_req();
	struct in_http_info *info = &I_INFO(cur_req);
	if (!parser)
		return -1;

	info->message_complete_cb_called = 1;
	/* this will make parser return "err"
	 * we should deal with the "err" carefully in parse_request
	 */
	return 1;
}

static int header_field_cb (http_parser *parser, const char *buf, size_t len)
{
#if 0
	struct request *cur_req = get_cur_req();
#endif
	if (!parser)
		return -1;
	
	return 0;
#if 0
	if (I_INFO(cur_req).last_header_element != FIELD)
		I_INFO(cur_req).num_headers++;
	I_INFO(cur_req).headers[I_INFO(cur_req).num_headers-1].f_len += len;

	if ((I_INFO(cur_req).num_headers = MAX_HEADERS) || (I_INFO(cur_req).headers[I_INFO(cur_req).num_headers-1].f_len >= MAX_ELEMENT_SIZE)) {
		seterrstatus(cur_req, BAD_REQUEST);
		return -1;
		return 0;
	}
	strncat(I_INFO(cur_req).headers[I_INFO(cur_req).num_headers-1].f, buf, len);
	I_INFO(cur_req).last_header_element = FIELD;

	return 0;
#endif
}

static int header_value_cb (http_parser *parser, const char *buf, size_t len)
{
#if 0
	struct request *cur_req = get_cur_req();
	struct in_http_info *info = &I_INFO(cur_req);
	if (!parser)
		return -1;

	info->headers[info->num_headers-1].v_len += len;
	if (info->headers[info->num_headers-1].v_len >= MAX_ELEMENT_SIZE) {
		seterrstatus(cur_req, BAD_REQUEST);
		return -1;
		return 0;
	}
	strncat(info->headers[info->num_headers-1].v, buf, len);
	info->last_header_element = FIELD;
#endif
	return 0;
}

static int body_cb (http_parser *parser, const char *buf, size_t len)
{
#if 0
	struct request *cur_req = get_cur_req();
	struct in_http_info *info = &I_INFO(cur_req);
	if (!parser)
		return -1;

	info->body_len += len;
	if (info->body_len > MAX_BODY_SIZE) {
		seterrstatus(cur_req, REQUEST_ENTITY_TOO_LARGE);
		return -1;
	}
	strncat(info->body, buf, len);
#endif
	return 0;
}

static int request_url_cb (http_parser *parser, const char *buf, size_t len)
{
	struct request *cur_req = get_cur_req();
	struct in_http_info *info = &I_INFO(cur_req);
	if (!parser)
		return -1;

	info->request_url_len += len;
	if (info->request_url_len > MAX_URL_SIZE) {
		seterrstatus(cur_req, REQUEST_URI_TOO_LONG);
		return -1;
	}
	strncat(info->request_url, buf, len);
	return 0;
}

static http_parser_settings settings ={
	.on_message_begin = message_begin_cb,
	.on_header_field = header_field_cb,
	.on_header_value = header_value_cb,
	.on_url = request_url_cb,
	.on_body = body_cb,
	.on_headers_complete = headers_complete_cb,
	.on_message_complete = message_complete_cb,
};

/* parser indicates wrong http format, return -1. ask for close.
 * let's send back a response, return 0.
 * request not complete, return 1
 */
int parse_request(struct request *req)
{
	size_t nparsed;

	if (!req) {
		
		return -1;
	}
	if (!req->parser_inited) {
		http_parser_init(&req->parser, HTTP_REQUEST);
		req->parser_inited = 1;
	}

	set_cur_req(req);

	nparsed = http_parser_execute(&req->parser, &settings, req->in_http + req->in_http_cur, req->in_http_len - req->in_http_cur);
	/* if parser says wrong and it is not because us
	 * XXX when we support keep-alive in the future,
	 * we may break the parser intendedly
	 */
	if (nparsed != req->in_http_len - req->in_http_cur && !I_INFO(req).message_complete_cb_called) {
		req->in_http_err = 1;
		return -1;
	}

	req->in_http_cur += nparsed;

	if (I_INFO(req).message_complete_cb_called) {
		I_INFO(req).message_complete_cb_called = 0;
		return 0;
	}

	return 1;
}


int prepare_response(struct request *req)
{
	int n;
	
	struct stat s;

	if (!req) {
		return -1;
	}

	if (req->in_http_err)
		return 0;
/*
  l1 = strlen(server_root);
  l2 = strlen(in_info->request_path);
  if (l1 + l2 >= MAX_FD_PATH_SIZE) {
  seterrstatus(req, BAD_REQUEST);
  return -1;
  }

  strncat(info->fd_path, server_root, l1);
  strncat(in_info->request_path, in_info->request_path, l2);
*/

	if ((n = open(I_INFO(req).request_path, O_RDONLY | O_NOCTTY)) == -1) {
		seterrstatus(req, NOT_FOUND);
		return 0;
	}
	O_INFO(req).fd = n;

	if (((n = fstat(n, &s)) != 0) || !S_ISREG(s.st_mode)) {
		seterrstatus(req, NOT_FOUND);
		return 0;
	}
	O_INFO(req).fd_size = s.st_size;

	if (req->in_http_err) {
		return 0;
	}

	if (req->in_http_err == 0)
		setstatus(req, OK);

	return 0;
}

static int send_response(struct request *req)
{
	char buf[1024];
	int len = 0;
	int n = 1;
	struct out_http_info *info;

	if (!req) {
		return -1;
	}

	info = &O_INFO(req);

	
	n = snprintf(buf + len, sizeof(buf) - len,
		     "HTTP/1.1 %d %s\r\n",
		     O_INFO(req).status_code,
		     O_INFO(req).status_description);
	if (n == -1)
		return -1;
	len += n;


	if (req->in_http_err) {
		
		n = write(req->connfd, buf, len);
		if (n == -1)
			return -1;
		return 0;
	} else {
		

		
		n = snprintf(buf + len, sizeof(buf) - len,
			     "Connection: close\r\n");
		if (n == -1)
			return -1;
		len += n;

		if (O_INFO(req).fd_size) {
			n = snprintf(buf + len, sizeof(buf) - len,
				     "Content-length: %ld\r\n\r\n",
				     (long)(O_INFO(req).fd_size - 1));
			if (n == -1)
				return -1;
			len += n;
		}


		n = write(req->connfd, buf, len);
		if (n == -1)
			goto err;

		
		
		n = sendfile(req->connfd, O_INFO(req).fd, &O_INFO(req).fd_off, O_INFO(req).fd_size);
		if (n == -1)
			goto err;
	
		n = 0;
		return 0;

	err:
		n = 0;
		return -1;
	}
}

/* request not completed, return 1
 * serious err, return -1
 * send back OK, return 0
 */
int do_request(struct request *req)
{
	if (!req)
		return -1;
	
	switch(parse_request(req)) {
	case 0:	break;
	case -1: return -1;
	case 1: return 1;
	}
	
	if (prepare_response(req) == -1)
		return -1;
	if (send_response(req) == -1)
		return -1;

	return 0;
}
