#ifndef _SERVER_IMPL_H
#define _SERVER_IMPL_H

#include <arpa/inet.h>
#include "ringbuf.h"
#include "deque.h"

typedef int FD;

typedef struct _conn{

	FD fd;
	int events;
	pRingBuf rbuf;
	pRingBuf wbuf;

    void(*on_read)(struct _conn* conn);
    void(*on_write)(struct _conn* conn);
    void(*on_close)(struct _conn* conn);
    void(*write)(struct _conn* conn, char* src, size_t len);
    void(*handler)(void* loop, struct _conn* conn, int events, int signal); // 使用void* 而不是IOLoop, 是为了防止循环include, 有没有好办法？

    struct sockaddr_in addr;

} Conn;

struct ConnCache{
    // 这个available是个动态平衡的指标。 每get一个conn, 就会--, put一个就会++
    // 当available < 0 时, 每次put/get都会分配/释放内存, 所以要根据业务场景, 选择合适的初始available
    long available;
    pDeque deq;
};

typedef void(*onfunc)(Conn* conn);
typedef void(*write_conn_func)(Conn* conn, char* src, size_t len);

typedef struct  _tcpserver{
    unsigned short port;
	unsigned short backlog;
	in_addr_t addr;
    FD listenfd;
    Conn* _sconn;       // fake conn obj
    int(*start)(struct _tcpserver* server);
    struct _tcpserver*(*bind)(struct _tcpserver* server, in_addr_t addr, unsigned short port);
    struct _tcpserver*(*listen)(struct _tcpserver* server, unsigned short backlog);

    onfunc on_read;
    onfunc on_write;
    onfunc on_close;

} TCPServer;

typedef struct _udpserver{
    unsigned short port;
    in_addr_t addr;
    FD listenfd;
    Conn* _sconn;       // fake conn obj
    int(*start)(struct _udpserver* server);
    struct _udpserver*(*bind)(struct _udpserver* server, in_addr_t addr, unsigned short port);
    struct _udpserver*(*listen)(struct _udpserver* server);
    
    onfunc on_read;
    onfunc on_write;
    onfunc on_close;


}UDPServer;

int setnonblocking(FD fd );

TCPServer* new_tcpserver(onfunc on_read, onfunc on_write, onfunc on_close);
void dealloc_tcpserver(TCPServer* server);

UDPServer* new_udpserver(onfunc on_read, onfunc on_write, onfunc on_close);
void dealloc_udpserver(UDPServer* server);


void init_conn_cache(long available);
void free_conn_cache();

// 将已经关闭的conn放回cache, 必须是已经关闭的
void putback_tcpconn(Conn* conn);

// 将已经关闭的conn放回cache, 必须是已经关闭的
// udpconn在用完之后, 一定要记得放回去, 不然会内存泄露
void putback_udpconn(Conn* conn);

typedef void(*events_handler)(void* loop, Conn* conn, int events, int signal);

Conn* get_tcpconn(FD fd, events_handler handler);
Conn* get_udpconn(FD fd, events_handler handler);

void listen_handler(void* loop, Conn* conn, int events, int signal);
void conn_handler(void* loop, Conn* conn, int events, int signal);

size_t read_udpconn(void* loop, Conn* conn);
void write_udpconn(Conn* conn, char* src, size_t len);
#endif