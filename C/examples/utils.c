#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "utils.h"


static bool disable_output = false;
void pt_debug(const char *format, ...)
{
	if (disable_output)
	{
		return;
	}
        //printf("[PT] ");
        va_list va;
        va_start(va, format);
        vprintf(format, va);
        va_end(va);
}

int msleep(long ms)
{
	struct timespec ts;
	int res;

	if (ms < 0)
	{
		errno = EINVAL;
		return -1;
	}

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;

	do {
		res = nanosleep(&ts, &ts);
	} while (res && errno == EINTR);

	return res;
}
