#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "client.h"
#include "logger.h"
#include "ioloop.h"

#include "client.h"
#include "util.h"
#include "dns.h"


void on_dns_response(Conn* conn){
    RBSeg seg;
    ipaddr ip;
    if(!rb_readable(conn->rbuf, &seg)){
        return;
    }
    pParser parser =  new_dns_parser(seg.buf, seg.len);
    IPlist res = dns_parse_response(parser);

    size_t sz = IPLIST_SIZE(res);
    for(size_t i = 0; i< IPLIST_SIZE(res); i ++){
        ip = res[i];
        unsigned short qtype = IPADDR_QTYPE(ip);
        logdebug("%s", ip);
    }
    dealloc_iplist(res);
    dealloc_dnsparser(parser);

    close_udp_client(ioloop_current(), conn);
}


void test_dns(void* sdshost, int signal){

    char* req = build_dns_request( (char*)sdshost, SDS_LEN(sdshost), QTYPE_A, 12 );
    if(!req){
        logwarn("ERROR!");
        return;
    }
    Conn* conn = new_udp_client("10.246.3.33", 53, AF_INET);
    send_udp(conn, req, SDS_LEN(req), on_dns_response);

    dealloc_sds(sdshost);
    dealloc_sds(req);
}

void dns_timer(pIOLoop loop, long delay){
    pTimer timer = (pTimer)malloc(sizeof(Timer));
    const char host[] = "www.jd.com"; 
    sds sdshost = new_sds(sizeof(host) - 1);
    memcpy(sdshost, (char*)host, sizeof(host) - 1);

    timer->callback = test_dns;
    timer->due = tsnow() + delay;
    timer->vars = (void*)sdshost;
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
	putback_udpconn(conn);
}

void on_write(Conn* conn){
	logdebug("all data were written to buffer");
}

void on_close(Conn* conn){
	logdebug("conn closed!");
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


    set_loglevel(LOGLV_DEBUG);
	init_conn_cache(100);

    dns_timer(loop, 5);

    loop->serve_forever(loop);
    dealloc_ioloop(loop);
}
