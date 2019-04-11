#include <time.h>
#include <sys/timeb.h>
#include "util.h"

long tsnow(){
    struct timeb t;
    ftime(&t);
    return t.time*1000 + (long)t.millitm;
}