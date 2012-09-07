#include <stdio.h>
#include <signal.h>
#include <event2/event.h>
#include "signal.h"
#include "evhttp.h"

sigset_t sigmask;

static void sighup_handler(int a)
{
	fprintf(stderr, "recv SIGHUP\n");
	mainworker.sig_hup = 1;
	event_base_loopbreak(mainworker.base);
}

static void sigterm_handler(int a)
{
	fprintf(stderr, "recv SIGTERM\n");
	mainworker.sig_term = 1;
	event_base_loopbreak(mainworker.base);
}

static void sigquit_handler(int a)
{
	fprintf(stderr, "recv SIGQUIT\n");
	event_base_loopbreak(mainworker.base);
}

void init_signals()
{
	struct sigaction act;

	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGTERM);
	sigaddset(&act.sa_mask, SIGHUP);
	sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGQUIT);

	sigmask = act.sa_mask;

	act.sa_handler = sighup_handler;
	sigaction(SIGHUP, &act, NULL);

	act.sa_handler = sigterm_handler;
	sigaction(SIGTERM, &act, NULL);

	act.sa_handler = sigquit_handler;
	sigaction(SIGQUIT, &act, NULL);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, SIG_IGN);
}
