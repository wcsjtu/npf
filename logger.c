#include <time.h>
#include "logger.h"
#include "globals.h"

char* strnow() {
	time_t now;
	struct tm buf;
	time(&now);
#ifdef WIN32
	localtime_s(&buf, &now);
#else
	localtime_r(&now, &buf);
#endif
	strftime(nowbuf, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", &buf);
	return nowbuf;
}