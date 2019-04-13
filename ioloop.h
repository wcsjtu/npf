#ifndef _IOLOOP_H
#define _IOLOOP_H

#include <arpa/inet.h>
#include "deque.h"
#include "dict.h"
#include "heap.h"
#include "ringbuf.h"
#include "globals.h"

typedef int FD;
typedef void(*handler)(void* vars, int signal);

typedef struct _timer{
	long due;
	handler callback;
	void* vars;         // 如果有必要, 请在callback中释放内存
} Timer, *pTimer;

typedef struct _conn{

	FD fd;
	int events;
	pRingBuf rbuf;
	pRingBuf wbuf;

    void(*on_read)(struct _conn* conn);
    void(*on_write)(struct _conn* conn);
    void(*on_close)(struct _conn* conn);
    void(*write)(struct _conn* conn, char* src, size_t len);

} Conn;

typedef void(*onfunc)(Conn* conn);
typedef void(*write_conn_func)(Conn* conn, char* src, size_t len);

typedef struct  _server{
    unsigned short port;
	unsigned short backlog;
	in_addr_t addr;
    FD listenfd;
    Conn* _sconn;       // fake conn obj
    int(*start)(struct _server* server);
    struct _server*(*bind)(struct _server* server, in_addr_t addr, unsigned short port);
    struct _server*(*listen)(struct _server* server, unsigned short backlog);

    onfunc on_read;
    onfunc on_write;
    onfunc on_close;

} Server;



typedef struct _ioloop{
    int initial;
    int stop;
    pDeque ready;
    pHeap timers;
    size_t timer_cancels;
    pDict connections;
    FD efd;
	size_t fd_count;
    Server* server;

    void(*run_ready)(struct _ioloop* loop);
    void(*check_due_timer)(struct _ioloop* loop);
    void(*conn_register)(struct _ioloop* loop, Conn* conn);
    void(*conn_unregister)(struct _ioloop* loop, Conn* conn);
    void(*conn_modregister)(struct _ioloop* loop, Conn* conn);

    void(*conn_handler)(struct _ioloop* loop, Conn* conn, int events, int signal);
    void(*listen_handler)(struct _ioloop* loop, FD fd, int events, int signal);
    void(*serve_once)(struct _ioloop* loop);
    void(*serve_forever)(struct _ioloop* loop);

    void(*add_timer)(struct _ioloop* loop, pTimer timer);

} IOLoop, *pIOLoop;

extern IOLoop ioloop;

pIOLoop ioloop_current();
void dealloc_ioloop(IOLoop* loop);

void dealloc_server(Server* server);
Server* new_server(onfunc on_read, onfunc on_write, onfunc on_close);

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

*/

#endif