#ifndef _IOLOOP_H
#define _IOLOOP_H

#include <arpa/inet.h>
#include "deque.h"
#include "dict.h"
#include "heap.h"
#include "ringbuf.h"
#include "globals.h"
#include "server.h"
#include "sgdefs.h"

typedef void(*handler)(void* vars, Signal signal);

typedef struct _timer{
	long due;
	handler callback;
	void* vars;         // 如果有必要, 请在callback中释放内存
} Timer, *pTimer;


typedef struct _ioloop{

    int initial;
    int stop;
    pDeque ready;
    pHeap timers;
    size_t timer_cancels;
    pDict connections;
    FD efd;
	size_t fd_count;

    TCPServer* tcpserver;
    UDPServer* udpserver;

    void(*run_ready)(struct _ioloop* loop);
    void(*check_due_timer)(struct _ioloop* loop);
    int(*conn_register)(struct _ioloop* loop, Conn* conn);
    void(*conn_unregister)(struct _ioloop* loop, Conn* conn);
    int(*conn_modregister)(struct _ioloop* loop, Conn* conn);

    void(*serve_once)(struct _ioloop* loop);
    void(*serve_forever)(struct _ioloop* loop);

    void(*add_timer)(struct _ioloop* loop, pTimer timer);

} IOLoop, *pIOLoop;

extern IOLoop ioloop;

pIOLoop ioloop_current();
void dealloc_ioloop(IOLoop* loop);


/*

内存管理： 
1. 容器类型
    dict  只有在del_item时会释放key 和val的内存， 所以, 请及时del掉不用的数据
    heap  容器不会帮忙管理内存, 需要手动调用heapFreeEntry宏来释放
    deque 容器不会帮忙管理内存, 需要手动调用dequeFreeEntry宏来释放

2. buf类型
    ringbuf, 内存在register到epoll时分配, 在socket closed时释放

3. 服务类型
    Server 手动调用dealloc_server释放, 或者随着ioloop释放(dealloc_ioloop)

4. 缓存类型
    ConnCache, 会缓存capacity个实例

*/

/*
    服务退出时, 要做的事情:
        1. 清理loop->timer, 类型是Heap类型
        2. 清理loop->ready, 类型是Deque类型
        3. 清理ConnCache。UDPConnCache中的fd都没关闭. TCPConnCache中的fd都是关闭了的
        4. 主动关闭所有连接(TODO, 该怎么搞)
        5. 清理loop->tcpserver, loop->udpserver
        6. ...TODO
*/

#endif