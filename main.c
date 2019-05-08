#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "client.h"
#include "logger.h"
#include "ioloop.h"

#include "client.h"
#include "util.h"
#include "dns.h"
#include "sgdefs.h"



void on_resolved(void* res, Signal sg){
    ipstr ip = (ipstr)res;
    if(sg != SG_OK){
        logwarn("resolve failed");
        return;
    }
        
    while (ip){
        loginfo("%s", ip);
        ip = IPSTR_NEXT(ip);
    }
}


void test_dns(void* sdshost, Signal signal){
    resolve("www.163.com1", AF_INET, on_resolved);
}

void dns_timer(pIOLoop loop, long delay){
    pTimer timer = (pTimer)malloc(sizeof(Timer));
    timer->callback = test_dns;
    timer->due = tsnow() + delay;
    timer->vars = NULL;
    loop->add_timer(loop, timer);
}

// server

void on_read(Conn* conn){
	//printf("fd %d on read]\n", conn->fd);
    RBSeg seg;
	conn->write(conn, "[Server]", 8);
	conn->write(conn, strnow(), TIME_BUF_SIZE);
	while( rb_readable(conn->rbuf, &seg) ){
		//fwrite(seg.buf, seg.len, 1, stdout);
		rb_start_forward(conn->rbuf, seg.len);
		conn->write(conn, seg.buf, seg.len);
	}
}

void on_udpread(Conn* conn){
	RBSeg seg;
	while( rb_readable(conn->rbuf, &seg) ){
		//fwrite(seg.buf, seg.len, 1, stdout);
		rb_start_forward(conn->rbuf, seg.len);
		conn->write(conn, seg.buf, seg.len);
	}
    close_udpconn(ioloop_current(), conn);
	putback_udpconn(conn);
}

void on_write(Conn* conn){
	logdebug("all data were written to buffer");
}

void on_close(Conn* conn){
    char ip[INET6_ADDRSTRLEN] = {0};
    struct sockaddr_in addr = conn->addr;
    if(inet_ntop(addr.sin_family, &(addr.sin_addr), ip, INET6_ADDRSTRLEN) == NULL){
        logwarn("ntop error: %d", errno);
        return;
    }
    
	loginfo("Bye %s:%d", ip, addr.sin_port);
}



int main(){
    IOLoop* loop = ioloop_current();


    TCPServer* tcpserver = new_tcpserver(on_read, on_write, on_close);

    tcpserver->bind(tcpserver, 0, 28080)->listen(tcpserver, 128);

    if(!tcpserver->start(tcpserver)){
        dealloc_tcpserver(tcpserver);
        return -1;
    }

	UDPServer* udpserver = new_udpserver(on_udpread, on_write, on_close);
	udpserver->bind(udpserver, 0, 28080);

	if(!udpserver->start(udpserver)){
		dealloc_udpserver(udpserver);
		return -1;
	}


    set_loglevel(LOGLV_INFO);
	init_conn_cache(100);
    init_dns_cache(1 << 6);

    dns_timer(loop, 5);

    loop->serve_forever(loop);
    dealloc_ioloop(loop);
}
