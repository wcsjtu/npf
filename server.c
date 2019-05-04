#include <netdb.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "logger.h"
#include "server.h"
#include "ioloop.h"
#include "util.h"

#define MAX_BUF_SIZE 10240L             // ringbuf 最大大小
#define MAX_UDP_PACKAGE_SIZE 65535      // UDP单个数据报的最大长度


struct ConnCache _tcp_conn_cache = {0};
struct ConnCache _udp_conn_cache = {0};


int setnonblocking(FD fd )
{
	if( fcntl( fd, F_SETFL, fcntl( fd, F_GETFD, 0 )|O_NONBLOCK ) == -1 )
	{
		logerror("Set blocking error : %d\n", errno);
		return -1;
	}
	return 0;
}


// Conn define

// 写入缓存
static void write_to_buf(Conn* conn, char* src, size_t len){
	RBSeg seg;
	size_t wn = 0, n = 0;
	pIOLoop loop = ioloop_current();
	if(len <= 0)
		return;
	if(!(conn->events & EPOLLOUT)){
		conn->events |= EPOLLOUT;
		loop->conn_modregister(loop, conn);
	}
	
	while(wn < len){
		if(!rb_writable(conn->wbuf, &seg)){
			loop->serve_once(loop);
		} else{
			n = MIN(seg.len, len - wn);
			memcpy(seg.buf, src + wn, n);
			rb_end_forward(conn->wbuf, n);
			wn += n;
		}
	}
}

static Conn* _new_conn(
        FD fd, 
        events_handler handler,
        size_t rbsize,
        size_t wbsize){
    Conn* conn = NULL;

    if(rbsize > MAX_BUF_SIZE || wbsize > MAX_BUF_SIZE){
        logwarn("buffer size exceeds MAX_BUF_SIZE %lu", MAX_BUF_SIZE);
        return NULL;
    }

	if( (conn = (Conn*)malloc(sizeof(Conn))) == NULL ){
		return NULL;
	}
    memset(conn, 0, sizeof(Conn));
	conn->fd = fd;
    if(rbsize){
        conn->rbuf = new_ringbuf(rbsize);
        if(conn->rbuf == NULL){
            free(conn);
            return NULL;
        }
    }
	if(wbsize){
        conn->wbuf = new_ringbuf(wbsize);
        if(conn->rbuf == NULL){
            free(conn);
            dealloc_ringbuf(conn->rbuf);
            return NULL;
        }
    }
    conn->handler = handler;
	return conn;
}

#define _NEW_TCP_CONN(fd, h) _new_conn(fd, h, MAX_BUF_SIZE, MAX_BUF_SIZE)
#define _NEW_UDP_CONN(fd, h) _new_conn(fd, h, MAX_BUF_SIZE, 0)

// 释放conn占用的内存
static void _dealloc_conn(Conn* conn){
	if(conn->rbuf){
		dealloc_ringbuf(conn->rbuf);
	}
	if(conn->wbuf){
		dealloc_ringbuf(conn->wbuf);
	}
	free(conn);
}

// 清空conn中的数据, 但是保留buf
static void _reset_conn(Conn* conn){
    pRingBuf rbuf=NULL, wbuf=NULL;
    if(conn->rbuf){
        rbuf = conn->rbuf;
        REST_RINGBUF(rbuf);
    }
    if(conn->wbuf){
        wbuf = conn->wbuf;
        REST_RINGBUF(wbuf);
    }
    memset(conn, 0, sizeof(Conn));
    conn->wbuf = wbuf;
    conn->rbuf = rbuf;
}

// 从cache中/或者new一个conn实例
static Conn* _get_conn(struct ConnCache* cache, FD fd, events_handler handler){
    Conn* res = NULL;
    if(cache->deq->count){
        res = (Conn*)(deque_pop(cache->deq)->val);
    } else{
        if (cache == &_tcp_conn_cache){
            res = _NEW_TCP_CONN(fd, handler);
        } else if(cache == &_udp_conn_cache){
            res = _NEW_UDP_CONN(fd, handler);
        } else{
            logwarn("bad call");
        }
    }
    
    if(res)
        cache->available--;
    res->fd = fd;
    res->handler = handler;
    return res;
}

Conn* get_tcpconn(FD fd, events_handler handler){
    return _get_conn(&_tcp_conn_cache, fd, handler);
}

Conn* get_udpconn(FD fd, events_handler handler){
    return _get_conn(&_udp_conn_cache, fd, handler);
}

// 将已经关闭的conn放回cache, 必须是已经关闭的
static void _putback_conn(struct ConnCache* cache, Conn* conn){
    if(cache->available < 0){
        _dealloc_conn(conn);
    } else{
        _reset_conn(conn);
        deque_append(cache->deq, (void*)conn);
    }
    cache->available ++ ;
}

// 将已经关闭的conn放回cache, 必须是已经关闭的
void putback_tcpconn(Conn* conn){
    _putback_conn(&_tcp_conn_cache, conn);
}

// 将已经关闭的conn放回cache, 必须是已经关闭的
void putback_udpconn(Conn* conn){
    _putback_conn(&_udp_conn_cache, conn);
}

static void _close_conn(void* _loop, Conn* conn){

    pIOLoop loop = (pIOLoop)_loop;
    loop->conn_unregister(loop, conn);
	conn->on_close(conn);		//	执行回调
	close(conn->fd);
}

static size_t _read_conn(pIOLoop loop, Conn* connection){
	RBSeg seg;
	long rn = 0, total = 0;
	int fd = connection->fd;
	while( rb_writable(connection->rbuf, &seg) ){
		rn = read(fd, seg.buf, seg.len);
		if(rn < 0){
			if(errno == EAGAIN)
				break;
			return 0;
		}
		else if(rn == 0){
			return 0;
		}
		else{
			total += rn;
			rb_end_forward(connection->rbuf, rn);
			if(rn < seg.len)
				break;
		}
	}
	return total;
}

static size_t _write_conn(pIOLoop loop, Conn* connection){
	RBSeg seg;
	long wn = 0, total=0;
	int fd = connection->fd;
	while( rb_readable(connection->wbuf, &seg) ){
		wn = write(fd, seg.buf, seg.len);
		if(wn < 0 ){
			if(errno == EAGAIN){
				break;
			}
			_close_conn(loop, connection);
            _putback_conn(&_tcp_conn_cache, connection);
			return 0;
		}
		total += wn;
		rb_start_forward(connection->wbuf, wn);
	}
	return total;
}



static FD _create_bind(in_addr_t addr, int socktype, unsigned short port){
    FD listen_fd;
    struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(addr);
    saddr.sin_port = htons(port);
    if( (listen_fd = socket(AF_INET, socktype, 0)) == -1 ){
		logerror("failed to create server socket!");
		return -1;
	}
    if(-1 == setnonblocking(listen_fd)){
		return -1;
	}
    if (  bind(listen_fd, (struct sockaddr*)&saddr, sizeof(struct sockaddr)) == -1 ){
		logerror("fail to bind server socket");
		return -1;
	}
	return listen_fd;
}

// TCPServer definition

static int _tcpserver_start(TCPServer* server){
    server->listenfd = _create_bind(server->addr, SOCK_STREAM, server->port);
    if(server->listenfd == -1){
        return 0;
    }
    if(setsockopt(server->listenfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
		logerror("set REUSE_ADDR to listen fd error: %d", errno);
		return 0;
	}
    if(listen(server->listenfd, server->backlog) == -1){
		logerror("listen port %d error: errno=%d", server->port, errno);
		return 0;
	}
    server->_sconn = _new_conn(server->listenfd, listen_handler, 0, 0);
    if(server->_sconn == NULL){
        return 0;
    }
    server->_sconn->addr.sin_port = server->port;
    // TODO 

    server->_sconn->events = EPOLLIN | EPOLLERR | EPOLLET;
    loginfo("TCPSERVER:  listen port %d", server->port);
    ioloop.tcpserver = server;       
    return 1;
}

static TCPServer* _tcpserver_bind(TCPServer* server, in_addr_t addr, unsigned short port){
    server->addr = addr;
    server->port = port;
    return server;
}

static TCPServer* _tcpserver_listen(TCPServer* server, unsigned short backlog){
    server->backlog = backlog;
    return server;
}

TCPServer* new_tcpserver(onfunc on_read, onfunc on_write, onfunc on_close){
    TCPServer* server = (TCPServer*)malloc(sizeof(TCPServer));
    if(server == NULL){
        logerror("Out of memory when create TCPServer");
        exit(EXIT_FAILURE);
    }
    server->start = _tcpserver_start;
    server->bind = _tcpserver_bind;
    server->listen = _tcpserver_listen;
	server->on_read = on_read;
	server->on_write = on_write;
	server->on_close = on_close;
    return server;
}

void dealloc_tcpserver(TCPServer* server){
    if(server->_sconn){
        free(server->_sconn);
    }
    free(server);
}

// UDPServer define



static UDPServer* _udpserver_bind(UDPServer* server, in_addr_t addr, unsigned short port){
    server->addr = addr;
    server->port = port;
    return server;
}



void dealloc_udpserver(UDPServer* server){
    if(server->_sconn){
        free(server->_sconn);
    }
    free(server);
}



void listen_handler(void* _loop, Conn* sconn, int events, int signal){
    pIOLoop loop = (pIOLoop)_loop;
    Conn* cconn = NULL;
    FD fd = sconn->fd;
    socklen_t	len = sizeof( struct sockaddr_in );
    if(events & EPOLLIN){
        cconn = _get_conn(&_tcp_conn_cache, 0, conn_handler);
        if(cconn == NULL){
            logwarn("Out of memory when new Conn");
            return;
        }
        int conn_fd = accept(fd, (struct sockaddr*)&(cconn->addr), &len);
        if(conn_fd == -1){
			logwarn("accept new connect error");
			return;
		}

        cconn->fd = conn_fd;
        cconn->events = EPOLLIN | EPOLLET | EPOLLERR;
        loop->conn_register(loop, cconn);

        cconn->on_read = loop->tcpserver->on_read;
        cconn->on_write = loop->tcpserver->on_write;
        cconn->on_close = loop->tcpserver->on_close;
        cconn->write = write_to_buf;
    }
    if(events & EPOLLERR){
        logerror("listen fd error: errno=%d", errno);
		exit(EXIT_FAILURE);
    }
}

void conn_handler(void* _loop, Conn* conn, int events, int signal){
    pIOLoop loop = (pIOLoop)_loop;
    long rn = 0;
    int new_events = EPOLLERR | EPOLLET, fd = conn->fd;
    // event handle
    if(events & EPOLLERR){
		logerror("fd %d error: errno=%d", fd, errno);
		_close_conn(_loop, conn);
        _putback_conn(&_tcp_conn_cache, conn);
		return;
	}

    if(events & EPOLLIN){
		rn = _read_conn(loop, conn);
		if(rn > 0){
			conn->on_read(conn);
		}else{
			_close_conn(_loop, conn);
            _putback_conn(&_tcp_conn_cache, conn);
			return;
		}
	}

    if(events & EPOLLOUT){
		size_t nw = _write_conn(loop, conn);
	}

    // new event
    if( !rb_empty(conn->wbuf) ){
		new_events |= EPOLLOUT;
	}
    if(!rb_full(conn->rbuf)){
		new_events |= EPOLLIN;
	}
    if (new_events != conn->events){
		conn->events = new_events;
        loop->conn_modregister(loop, conn);
	}
}

void close_udpconn(void* _loop, Conn* conn){
    //pIOLoop loop = (pIOLoop)_loop;
    //loop->conn_unregister(loop, conn);    // 因为udpconn用的是listen socket的fd， 所以不能close
    //close(conn->fd);
	conn->on_close(conn);		//	执行回调
	
}

// 将数据从socket读到read buffer中
size_t read_udpconn(void* _loop, Conn* conn){
    pIOLoop loop = (pIOLoop)_loop;
    RBSeg seg;
	long rn = 0, total = 0;
	int fd = conn->fd;
    socklen_t	len = sizeof( struct sockaddr_in );
	while( rb_writable(conn->rbuf, &seg) ){
		rn = recvfrom(fd, seg.buf, seg.len, 0, (struct sockaddr *)&(conn->addr), &len);
		if(rn < 0){
            logwarn("recvfrom error, errno=%d", errno);
			if(errno == EAGAIN)
				break;
			return 0;
		}
		else if(rn == 0){
			return total;
		}
		else{
			total += rn;
			rb_end_forward(conn->rbuf, rn);
			if(rn < seg.len)
				break;
		}
	}
	return total;
}

// 因为udp conn不提供write buffer, 所以调用这个函数, 会直接写socket
void write_udpconn(Conn* conn, char* src, size_t len){
    // TODO 要不要判断len是否大于UDP包的最大长度
    if(len > MAX_UDP_PACKAGE_SIZE){
        logwarn("size of package which need be sent by udp exceeds MAX_UDP_PACKAGE_SIZE");
    }
    int fd = conn->fd;
    long wn = 0;
    socklen_t	addrlen = sizeof( struct sockaddr_in );
    wn = sendto(fd, src, len, 0, (struct sockaddr*)&(conn->addr), addrlen);
    if(wn < 0){
        logwarn("UDP sendto error %d", errno);
    }
}


void udp_listen_handler(void* _loop, Conn* sconn, int events, int signal){
    pIOLoop loop = (pIOLoop)_loop;
    Conn* cconn = NULL;
    FD fd = sconn->fd;
    if(events & EPOLLIN){
        cconn = _get_conn(&_udp_conn_cache, fd, NULL); //使用listen socket的fd
        if(cconn == NULL){
            logwarn("Out of memory when new Conn(UDP)");
            return;
        }
        cconn->on_read = loop->udpserver->on_read;
        cconn->on_write = loop->udpserver->on_write;
        cconn->on_close = loop->udpserver->on_close;
        cconn->write = write_udpconn;

        long rn = read_udpconn(loop, cconn);
        if (rn > 0){
            cconn->on_read(cconn);
        }
    }
}

static int _udpserver_start(UDPServer* server){
    server->listenfd = _create_bind(server->addr, SOCK_DGRAM, server->port);
    if(server->listenfd == -1){
        return 0;
    }
    // if(setsockopt(server->listenfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
	// 	logerror("set REUSE_ADDR to listen fd error: %d", errno);
	// 	return 0;
	// }
    
    server->_sconn = _new_conn(server->listenfd, udp_listen_handler, 0, 0);
    if(server->_sconn == NULL){
        return 0;
    }
    server->_sconn->events = EPOLLIN | EPOLLERR | EPOLLET;
    loginfo("UDPSERVER:  listen port %d", server->port);
    ioloop.udpserver = server;       
    return 1;
}

UDPServer* new_udpserver(onfunc on_read, onfunc on_write, onfunc on_close){
    UDPServer* server = (UDPServer*)malloc(sizeof(UDPServer));
    if(server == NULL){
        logerror("Out of memory when create UDPServer");
        exit(EXIT_FAILURE);
    }
    memset(server, 0, sizeof(UDPServer));

    server->start = _udpserver_start;
    server->bind = _udpserver_bind;
    server->listen = NULL;
	server->on_read = on_read;
	server->on_write = on_write;
	server->on_close = on_close;
    return server;
}

// init func

static void _free_conn(void* _conn){
    Conn* conn = (Conn*)_conn;
    if(conn->rbuf){
		dealloc_ringbuf(conn->rbuf);
	}
	if(conn->wbuf){
		dealloc_ringbuf(conn->wbuf);
	}
	free(conn);
}

static DequeType _connDeqType = {
    NULL,
    _free_conn
};

void init_conn_cache(long available){
    _tcp_conn_cache.available = available;
    _tcp_conn_cache.deq = new_deque(&_connDeqType);

    _udp_conn_cache.available = available;
    _udp_conn_cache.deq = new_deque(&_connDeqType);
}

// static void _free_conn_cache(){
//     const int cache_list_count = 2;
//     struct ConnCache list[cache_list_count] = {_tcp_conn_cache, _udp_conn_cache};
//     int i = 0;
//     struct ConnCache cache;
//     while(i < cache_list_count){
//         cache = list[i];
//         while(cache.deq->count){
//             dequeFreeEntry(cache.deq, deque_popleft(cache.deq));
//         }
//         i++;
//     }
// }