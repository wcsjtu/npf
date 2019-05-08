#include <netdb.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "ioloop.h"
#include "util.h"
#include "logger.h"


#define MAX_CANCELS_TIMER 512
#define DEFAULT_EPOLL_TIMEOUT 3600000
#define MAX_EPOLL_EVENTS 1024
#define INIT_HEAP_SIZE 100

IOLoop ioloop = {0};    // loop

// 类型定义

static int is_timer_valid(void* ep){
	return ((pTimer)ep)->callback != NULL;
}

static void heap_timer_free(void* ep){
	pTimer timer = (pTimer)ep;
	if(timer){
		free(ep);
	}
}

static int timer_cmp(void* e1, void* e2){
	if( ((pTimer)e1)->due > ((pTimer)e2)->due)
		return 1;
	else if( ((pTimer)e1)->due == ((pTimer)e2)->due)
		return 0;
	return -1;
}

static void deque_timer_free(void* ep){
    pDequeEntry entry = (pDequeEntry)ep;
    if(entry->val){
        heap_timer_free(entry->val);
		entry->val = NULL;
    }
    free(entry);
}

static DequeType deqTimerType = {
	NULL,
	deque_timer_free
};

static HeapType heapTimerType = {
	timer_cmp,
	heap_timer_free,
	NULL,
	is_timer_valid
};

// IOLoop 定义

static void serve_once(pIOLoop loop){
	long timeout = DEFAULT_EPOLL_TIMEOUT;
	size_t waitfds = 0, i = 0;
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	Conn* conn;

	if(loop->stop)
		return;
	if(loop->ready->count)
		loop->run_ready(loop);
	loop->check_due_timer(loop);

	if(loop->ready->count){
		timeout = 0;
	} else if(loop->timers->used){
		timeout = ((pTimer)loop->timers->buf[0])->due - tsnow();
		timeout = timeout < 0 ? 0 : timeout;
	}
	
	if(  (waitfds = epoll_wait(loop->efd, evs, loop->fd_count, timeout)) == -1 ){
		logwarn("epoll wait error: errno=%d", errno);
		return;
	}

	for(i = 0; i < waitfds; i++){
		conn = (Conn*)(evs[i].data.ptr);
		conn->handler(loop, conn, evs[i].events, 0);
	}
}

static void serve_forever(pIOLoop loop){

    if(loop->tcpserver){
        if(!loop->conn_register(loop, loop->tcpserver->_sconn)){
			logerror("register TCP server fd faield: %d", errno);
			exit(-1);
		}
    }
	if(loop->udpserver){
        if(!loop->conn_register(loop, loop->udpserver->_sconn)){
			logerror("register UDP server fd faield: %d", errno);
			exit(-1);
		}
    }

    while(!loop->stop){
        loop->serve_once(loop);
    }
}


static int conn_modregister(pIOLoop loop, Conn* conn){
    struct epoll_event ev;
	ev.events = conn->events;
	ev.data.ptr = (void*)conn;
	if(epoll_ctl(loop->efd, EPOLL_CTL_MOD, conn->fd, &ev) < 0 ){
		logwarn("fail to mod fd");
		return 0;
	}
	return 1;
}

static void conn_unregister(pIOLoop loop, Conn* conn){
	if(!conn->registered)
		return;
	if(epoll_ctl(loop->efd, EPOLL_CTL_DEL, conn->fd, NULL) < 0){
		logwarn("unregister fd %d error, errno: %d", conn->fd, errno);
	} else{
		loop->fd_count--;
	}
	
}

static int conn_register(pIOLoop loop, Conn* conn){
    struct epoll_event ev;
	FD fd = conn->fd;

	ev.data.ptr = (void*)conn;
	ev.events = conn->events;

	if(epoll_ctl(loop->efd, EPOLL_CTL_ADD, fd, &ev) < 0 ){
		logwarn("fail to register FD %d with events %d to epoll", fd, conn->events);
		close(conn->fd);
		putback_tcpconn(conn);
		return 0;
	}
	loop->fd_count++;
	conn->registered = 1;
	return 1;
}

static void _heapify_timer(pIOLoop loop){
	if ( loop->timer_cancels > MAX_CANCELS_TIMER 
		&& loop->timer_cancels > (loop->timers->used >> 1) ){
			loop->timer_cancels = 0;
			heapify(loop->timers);
		}
}

static void check_due_timer(pIOLoop loop){
    long current_ts;
	HeapEntry timer = NULL;
	if(!loop->timers->used)
		return;
	current_ts = tsnow();
	while(loop->timers->used){
		timer = loop->timers->buf[0];
		if( invalidHeapEntry(loop->timers, timer) ){
			timer = heap_pop(loop->timers);
            heapFreeEntry(loop->timers, timer);     // 这是个无效的timer, 释放内存
			loop->timer_cancels--;
		} else if (  ((pTimer)timer)->due <= current_ts ){
            timer = heap_pop(loop->timers);
            // pop 出来后不释放内存, 它会转移到deque中, 从deque中pop后才释放
			deque_append(loop->ready, (void*)timer);
		} else{
			break;
		}

	}
	_heapify_timer(loop);
}

static void add_timer(pIOLoop loop, pTimer timer){
    heap_push(loop->timers, (HeapEntry)timer);
}

static void run_ready(pIOLoop loop){
    pTimer timer = NULL;
	handler cb = NULL;
    pDequeEntry entry = NULL;
	while(loop->ready->count){
        entry = deque_popleft(loop->ready);
		timer = (pTimer)(entry->val);
		cb = (handler)timer->callback;
		cb(timer->vars, SG_TIMEOUT);
        dequeFreeEntry(loop->ready, entry);
	}
}

pIOLoop ioloop_current(){
    if(ioloop.initial)
        return &ioloop;
    ioloop.ready = new_deque(&deqTimerType);
    if(!ioloop.ready){
		logerror("failed to create server.ready");
		exit(EXIT_FAILURE);
	}
    ioloop.timers = new_heap(INIT_HEAP_SIZE, &heapTimerType);
    if(!ioloop.timers){
		logerror("failed to create server.timers with size %d", INIT_HEAP_SIZE);
		exit(EXIT_FAILURE);
	}
    ioloop.efd = epoll_create(MAX_EPOLL_EVENTS);

    ioloop.connections = NULL;		// 没有初始化, 不知道存什么好
    ioloop.timer_cancels = 0;
    ioloop.stop = 0;
    ioloop.initial = 1;

    ioloop.serve_forever = serve_forever;
    ioloop.run_ready = run_ready;
    ioloop.check_due_timer = check_due_timer;
    ioloop.conn_register = conn_register;
    ioloop.conn_unregister = conn_unregister;
    ioloop.conn_modregister = conn_modregister;
    ioloop.serve_once = serve_once;
    ioloop.add_timer = add_timer;
    return &ioloop;
}

void dealloc_ioloop(IOLoop* loop){
    dealloc_deque(ioloop.ready);
    ioloop.ready = NULL;

    dealloc_heap(ioloop.timers);
    ioloop.timers = NULL;

    if(loop->tcpserver){
		dealloc_tcpserver(loop->tcpserver);
		loop->tcpserver = NULL;
	}
    if(loop->udpserver){
		dealloc_udpserver(loop->udpserver);
		loop->udpserver = NULL;
	}

    loop->initial = 0;
}


#ifdef TEST_TIMER

void cb(void* vars, Signal signal){
    logdebug("%s", (char*)vars);
    // 不需要释放内存
}


void test_timer(pIOLoop loop, long delay){
    pTimer timer = (pTimer)malloc(sizeof(Timer));
    timer->callback = cb;
    timer->due = tsnow() + delay;
    timer->vars = "hello world";

    loop->add_timer(loop, timer);

}

void on_read(Conn* conn){
	//printf("fd %d on read]\n", conn->fd);
    RBSeg seg;
	conn->write(conn, "[Server]", 8);
	conn->write(conn, strnow(), TIME_BUF_SIZE);
	while( rb_readable(conn->rbuf, &seg) ){
		fwrite(seg.buf, seg.len, 1, stdout);
		rb_start_forward(conn->rbuf, seg.len);
		conn->write(conn, seg.buf, seg.len);
	}
}

void on_udpread(Conn* conn){
	RBSeg seg;
	while( rb_readable(conn->rbuf, &seg) ){
		fwrite(seg.buf, seg.len, 1, stdout);
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

    IOLoop* loop = ioloop_current();

    #ifdef TEST_TIMER
	long mask = (1 << 16) - 1;

	for(int i = 0; i< 10; i ++){
		long delay = rand();
    	test_timer(loop, delay & mask);
	}
	
    #endif
	set_loglevel(LOGLV_DEBUG);
	init_conn_cache(100);

    loop->serve_forever(loop);
    dealloc_ioloop(loop);
}

#endif