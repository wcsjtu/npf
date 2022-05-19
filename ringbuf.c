#include <stdlib.h>
#include "logger.h"
#include "ringbuf.h"

#define MAX_RINGBUF_SIZE (1 << 20)

pRingBuf new_ringbuf(size_t size){

    pRingBuf rbuf = NULL;
    char* buf = NULL;

    if(size >= MAX_RINGBUF_SIZE || ( (buf = (char*)malloc(sizeof(char) * size) ) == NULL)){
        logwarn("Out of memory when new ring buffer with size %lu", size);
        return NULL;
        }
    if((rbuf = (pRingBuf)malloc(sizeof(RingBuf)) ) == NULL){
        logwarn("Out of memory when new ring buffer with size %lu", size);
        free(buf);
    }
    rbuf->size = size;
    rbuf->end = 0;
    rbuf->start = 0;
    rbuf->buf = buf;
    memset(rbuf->buf, 0, size);
    return rbuf;
}

void dealloc_ringbuf(pRingBuf buf){
    free(buf->buf);
    free(buf);
}


int rb_empty(pRingBuf buf){
    return buf->end == buf->start;
}

int rb_full(pRingBuf buf){
    return buf->end == (buf->start ^ buf->size);
}

/*
-----------------------------------------------------
*********      **************************************
-----------------------------------------------------
        e      s                                    n
=> e > n && s < n

-----------------------------------------------------
        ************
-----------------------------------------------------
        s          e                                n
=> (e > n && s > n) || (e < n && s < n)

-----------------------------------------------------
*****************************************************
-----------------------------------------------------
            s                                       n
            e
=> e == (s ^ n)     //full

-----------------------------------------------------

-----------------------------------------------------
                s                                   n
                e
=> e == n           //empty

*/

#define BUF_END(buf) (buf->end & (buf->size - 1))
#define BUF_START(buf) (buf->start & (buf->size - 1))

#define END_CROS(buf) (buf->end >= buf->size)
#define START_CROS(buf) (buf->start >= buf->size)


int rb_writable(pRingBuf buf, RBSeg* seg){
    if(buf->start == buf->end){
        buf->end = buf->start = 0;
        seg->buf = buf->buf;
        seg->len = buf->size;
        return seg->len;
    }
    else if( END_CROS(buf) && !START_CROS(buf)){
        seg->buf = buf->buf + BUF_END(buf);
        seg->len = buf->start - BUF_END(buf);
        return seg->len;
    }
    else if((END_CROS(buf) && START_CROS(buf)) || (!END_CROS(buf) && !START_CROS(buf))){
        seg->buf = buf->buf + BUF_END(buf);
        seg->len = buf->size - BUF_END(buf);
        return 1;
    }
    seg->buf = NULL;
    seg->len = 0;
    return 0;
}

int rb_readable(pRingBuf buf, RBSeg* seg){
    seg->buf = NULL;
    seg->len = 0;
    if (rb_empty(buf))
        return 0;

    seg->buf = buf->buf + BUF_START(buf);

    if (END_CROS(buf) && !START_CROS(buf))
        seg->len = buf->size - BUF_START(buf);
    else
        seg->len = BUF_END(buf) - BUF_START(buf);
    return seg->len;
}

void rb_end_forward(pRingBuf buf, size_t nbytes){
    buf->end = (buf->end + nbytes) & ( (buf->size << 1) - 1);
}

void rb_start_forward(pRingBuf buf, size_t nbytes){
    buf->start = (buf->start + nbytes) & ((buf->size << 1) - 1);
}

#ifdef  TEST_RINGBUF




int main(){

    pRingBuf ringbuf = new_ringbuf(16);
    RBSeg seg;

    while (rb_writable(ringbuf, &seg)){
        size_t wn = seg.len >> 1;
        memset(seg.buf, 'x', wn);
        rb_end_forward(ringbuf, wn);
        if (wn < seg.len)
            break;
    }

    while (rb_readable(ringbuf, &seg)){
        fwrite(seg.buf, seg.len >> 1, 1, stdout);
        rb_start_forward(ringbuf, seg.len >> 1);
        break;
    }

    while (rb_writable(ringbuf, &seg)){
        size_t wn = seg.len;
        memset(seg.buf, 'y', wn);
        rb_end_forward(ringbuf, wn);
        if (wn < seg.len)
            break;
    }

    while (rb_readable(ringbuf, &seg)){
        fwrite(seg.buf, seg.len, 1, stdout);
        rb_start_forward(ringbuf, seg.len);
    }

    return 0;

}

#endif //  TEST_RINGBUF