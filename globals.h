#ifndef _GLOBALS_HH
#define _GLOBALS_HH


#define TIME_BUF_SIZE 26

#ifdef WIN32

#include <process.h>
extern __declspec(thread) char nowbuf[TIME_BUF_SIZE];

#else
#include <pthread.h>
extern __thread char nowbuf[TIME_BUF_SIZE];

#endif // WIN32





#endif // !_GLOBALS_HH

#pragma once
