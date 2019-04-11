#ifndef _RINGBUF_H
#define _RINGBUF_H

#include <string.h>

typedef struct _ringbuf{

    size_t size;    // buf 大小
    size_t start;    // 数据开始的位置
    size_t end;    // 数据结束的位置
    char* buf;

} RingBuf, *pRingBuf;

typedef struct _rbseg{
    char* buf;
    size_t len;
} RBSeg;

pRingBuf new_ringbuf(size_t size);
void dealloc_ringbuf(pRingBuf ringbuf);
int rb_empty(pRingBuf buf);
int rb_full(pRingBuf buf);
int rb_writable(pRingBuf buf, RBSeg* seg);
int rb_readable(pRingBuf buf, RBSeg* seg);
void rb_start_forward(pRingBuf buf, size_t nbytes);
void rb_end_forward(pRingBuf buf, size_t nbytes);

#endif