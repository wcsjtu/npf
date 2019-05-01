#ifndef _LOGGER_H
#define _LOGGER_H

#pragma once

#include <stdio.h>
#include <stdlib.h>

int loglv;
char* strnow();


#ifdef WIN32
#define __func__ __FUNCTION__
#endif // WIN32

enum LOG_LEVEL{
    LOGLV_DEBUG = 0,
    LOGLV_INFO = 10,
    LOGLV_WARN = 20,
    LOGLV_ERROR = 30
};



#define print(a, ...) printf("%s(%s:%d) " a,  __func__,__FILE__, __LINE__, ##__VA_ARGS__)
#define println(a, ...) print(a "\n", ##__VA_ARGS__)


//#define logger(level, format, ...) ( fprintf(stdout, "[%s %s:%d:%s] %s " format "\n", strnow(), __FILE__, __LINE__, __func__, level, ##__VA_ARGS__) )

#define logger(level, lv, format, ...) do { \
    if (lv >= loglv) \
        fprintf(stdout, "[%s %s:%d:%s] %s " format "\n", strnow(), __FILE__, __LINE__, __func__, level, ##__VA_ARGS__); \
    } while(0)


#define logdebug(format, ...) logger("DEBUG", LOGLV_DEBUG, format, ##__VA_ARGS__ )
#define loginfo(format, ...) logger("INFO ", LOGLV_INFO, format, ##__VA_ARGS__)
#define logwarn(format, ...) logger("WARN ", LOGLV_WARN, format, ##__VA_ARGS__)
#define logerror(format, ...) logger("ERROR", LOGLV_ERROR, format, ##__VA_ARGS__)

void set_loglevel(enum LOG_LEVEL lv);

#endif // !_LOGGER_H


