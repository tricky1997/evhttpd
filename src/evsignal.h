#ifndef _EVSIGNAL_H_
#define _EVSIGNAL_H_
#include <signal.h>

extern sigset_t sigmask;

void init_signals();

#endif
