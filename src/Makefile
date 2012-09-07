CC=gcc
LIBEVENT=/home/worker/program/libevent
CFLAGS= -Wall -Wextra  -g -DDEBUG -DHTTP_PARSER_STRICT=0 -DHTTP_PARSER_DEBUG=0 -I $(LIBEVENT)/include
SRCS=http.c http_parser.c evhttp.c evsignal.c
OBJS=$(SRCS:%.c=%.o)
LDFLAGS=-L $(LIBEVENT)/lib -levent -lpthread

.PHONY:clean


evhttp: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

lis: lis.o
	$(CC) $^ -o $@

clean:
	rm -f evhttp $(OBJS) lis.o
