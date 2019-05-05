#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "client.h"
#include "logger.h"

static void _udp_events_handler(void* _loop, UDPClient* cli, int events, int signal){
    pIOLoop loop = (pIOLoop)_loop;
    if(events & EPOLLIN){
        long rn = read_udpconn(loop, cli);
        if(rn > 0){
            cli->on_read(cli);
        }
    }
    if(events & EPOLLERR){
        logwarn("UDP client read error: %d", errno);
    }
}

UDPClient* new_udp_client(const char* addr, unsigned short port, int family){
    FD fd;
    if(family == AF_INET6){
        logwarn("IPv6 not supported now!");
        return NULL;
    }
    UDPClient* cli = get_udpconn();
    if(cli->fd <= 0){
        fd = create_udp_fd(family);
        if(fd <= 0){
            putback_udpconn(cli);
            return NULL;
        }
    }
    cli->handler = _udp_events_handler;
    cli->fd = fd;
    cli->addr.sin_family = family;
    cli->addr.sin_port = htons(port);
    cli->events = EPOLLIN | EPOLLERR | EPOLLET;
    if(inet_pton(family, addr, &cli->addr.sin_addr) != 1){
        logwarn("invalid ipaddr, errno: %d", errno);
        putback_udpconn(cli);
        return NULL;
    }
    return cli;
}

// UDP客户端发送数据, 如果成功, 则返回发送的字节数, 如果失败, 则返回负数
long udpclient_send(UDPClient* cli, char* buf, size_t len, onfunc on_read){
    pIOLoop loop = ioloop_current();
    cli->on_read = on_read;
    if(!loop->conn_register(loop, cli)){
        return -1;
    }
    return write_udpconn(cli, buf, len);
}

void udpclient_close(pIOLoop loop, UDPClient* cli){
    close_udpconn(loop, cli);
    putback_udpconn(cli);
}