#ifndef _SERVER_IMPL_H
#define _SERVER_IMPL_H

#include <arpa/inet.h>
#include "ringbuf.h"
#include "deque.h"
#include "sgdefs.h"

typedef int FD;

typedef struct _conn{

	FD fd;
	int events;
    int registered;     // 是否注册到了epoll
	pRingBuf rbuf;
	pRingBuf wbuf;

    void(*on_read)(struct _conn* conn);
    void(*on_write)(struct _conn* conn);
    void(*on_close)(struct _conn* conn);
    long(*write)(struct _conn* conn, char* src, size_t len);
    void(*handler)(void* loop, struct _conn* conn, int events, Signal signal); // 使用void* 而不是IOLoop, 是为了防止循环include, 有没有好办法？
    void* extra;        // 可以是任何东西
    struct sockaddr_in addr;

} Conn;

#define VALID_CONN(conn) (conn->fd > 0 ? 1 : 0)

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

typedef void(*events_handler)(void* loop, Conn* conn, int events, Signal signal);

Conn* get_tcpconn();
Conn* get_udpconn();

void listen_handler(void* loop, Conn* conn, int events, Signal signal);
void conn_handler(void* loop, Conn* conn, int events, Signal signal);

size_t read_udpconn(void* loop, Conn* conn);
long write_udpconn(Conn* conn, char* src, size_t len);

// 关闭UDP conn, 但是不会关闭FD
void close_udpconn(void* loop, Conn* conn);

// 关闭TCP conn, 同时也会关闭FD
void close_tcpconn(void* loop, Conn* conn);

// 打开一个新的UDP FD. 返回打开的FD, 失败则返回负数
FD create_udp_fd(int family);
#endif