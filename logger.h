#ifndef _LOGGER_H
#define _LOGGER_H

#pragma once

#include <stdio.h>
#include <stdlib.h>


char* strnow();


#ifdef WIN32
#define __func__ __FUNCTION__
#endif // WIN32


#define print(a, ...) printf("%s(%s:%d) " a,  __func__,__FILE__, __LINE__, ##__VA_ARGS__)
#define println(a, ...) print(a "\n", ##__VA_ARGS__)


#define logger(level, format, ...) ( printf("[%s %s:%d:%s] %s " format "\n", strnow(), __FILE__, __LINE__, __func__, level, ##__VA_ARGS__) )

#define logdebug(format, ...) logger("DEBUG", format, ##__VA_ARGS__ )
#define loginfo(format, ...) logger("INFO ", format, ##__VA_ARGS__)
#define logwarn(format, ...) logger("WARN ", format, ##__VA_ARGS__)
#define logerror(format, ...) logger("ERROR", format, ##__VA_ARGS__)

#endif // !_LOGGER_H


