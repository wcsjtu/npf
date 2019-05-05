#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "client.h"
#include "logger.h"

static void _udp_events_handler(void* _loop, Conn* conn, int events, int signal){
    pIOLoop loop = (pIOLoop)_loop;
    FD fd = conn->fd;
    if(events & EPOLLIN){
        long rn = read_udpconn(loop, conn);
        if(rn > 0){
            conn->on_read(conn);
        }
    }
    if(events & EPOLLERR){
        logwarn("UDP client read error: %d", errno);
    }
}

Conn* new_udp_client(const char* addr, unsigned short port, int family){
    FD fd;
    if(family == AF_INET6){
        logwarn("IPv6 not supported now!");
        return NULL;
    }
    Conn* conn = get_udpconn(0, _udp_events_handler);
    if(!conn){
        logwarn("failed to new UDP client");
        return NULL;
    }

    if( (fd = socket(family, SOCK_DGRAM, 0)) < 0 ){
        logwarn("Fail to new UDP client, socket created error: %d", errno);
        return NULL;
    }
    if(-1 == setnonblocking(fd)){
        logwarn("Fail to new UDP client, set socket to nonblocking error: %d", errno);
        return NULL;
    }
    conn->fd = fd;
    conn->addr.sin_family = family;
    conn->addr.sin_port = htons(port);
    conn->events = EPOLLIN | EPOLLERR | EPOLLET;
    inet_pton(family, addr, &conn->addr.sin_addr);
    return conn;
}

void send_udp(Conn* conn, char* buf, size_t len, onfunc on_read){
    pIOLoop loop = ioloop_current();
    conn->on_read = on_read;
    loop->conn_register(loop, conn);
    write_udpconn(conn, buf, len);
}

void close_udp_client(pIOLoop loop, Conn* conn){
    loop->conn_unregister(loop, conn);
    close(conn->fd);
    putback_udpconn(conn);
}