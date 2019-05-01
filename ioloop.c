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

#define MAX_BUF_SIZE 4096
#define MAX_CANCELS_TIMER 512
#define DEFAULT_EPOLL_TIMEOUT 3600000
#define MAX_EPOLL_EVENTS 1024
#define INIT_HEAP_SIZE 100

// Conn定义

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

static int setnonblocking( int fd )
{
	if( fcntl( fd, F_SETFL, fcntl( fd, F_GETFD, 0 )|O_NONBLOCK ) == -1 )
	{
		logerror("Set blocking error : %d\n", errno);
		return -1;
	}
	return 0;
}

// 写入缓存
void write_to_buf(Conn* conn, char* src, size_t len){
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

static Conn* new_conn(FD fd){
	Conn* conn = NULL;

	if( (conn = (Conn*)malloc(sizeof(Conn))) == NULL ){
		return NULL;
	}
	conn->fd = fd;

	conn->rbuf = new_ringbuf(MAX_BUF_SIZE);
	if(conn->rbuf == NULL){
		free(conn);
		return NULL;
	}
	conn->wbuf = new_ringbuf(MAX_BUF_SIZE);
	if(conn->rbuf == NULL){
		free(conn);
		dealloc_ringbuf(conn->rbuf);
		return NULL;
	}
    
	return conn;
} 

static void dealloc_conn(Conn* conn){
	if(conn->rbuf){
		dealloc_ringbuf(conn->rbuf);
	}
	if(conn->wbuf){
		dealloc_ringbuf(conn->wbuf);
	}
	free(conn);
}

static void close_conn(pIOLoop loop, Conn* conn){
	//("close fd %d", conn->fd);
    loop->conn_unregister(loop, conn);
	conn->on_close(conn);		//	执行回调
	close(conn->fd);
	dealloc_conn(conn);
}

static size_t read_conn(pIOLoop loop, Conn* connection){
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

static size_t write_conn(pIOLoop loop, Conn* connection){
	RBSeg seg;
	long wn = 0, total=0;
	int fd = connection->fd;
	while( rb_readable(connection->wbuf, &seg) ){
		wn = write(fd, seg.buf, seg.len);
		if(wn < 0 ){
			if(errno == EAGAIN){
				break;
			}
			close_conn(loop, connection);
			return 0;
		}
		total += wn;
		rb_start_forward(connection->wbuf, wn);
	}
	return total;
}

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
		if( conn->fd == loop->server->listenfd){
			loop->listen_handler(loop, loop->server->listenfd, evs[i].events, 0);
		} else{
			loop->conn_handler(loop, conn, evs[i].events, 0);
		}
	}
}

static void serve_forever(pIOLoop loop){

    if(loop->server){
        loop->conn_register(loop, loop->server->_sconn);
    }

    while(!loop->stop){
        loop->serve_once(loop);
    }
}

static void listen_handler(pIOLoop loop, FD fd, int events, int signal){
    struct sockaddr_in cliaddr;
    Conn* conn = NULL;
    socklen_t	len = sizeof( struct sockaddr_in );
    if(events & EPOLLIN){
        int conn_fd = accept(fd, (struct sockaddr*)&cliaddr, &len);
        if(conn_fd == -1){
			logwarn("accept new connect error");
			return;
		}
        conn = new_conn(conn_fd);
        if(conn == NULL){
            logwarn("fail to new conn to fd %d", conn_fd);
            close(conn_fd);
        }
        conn->events = EPOLLIN | EPOLLET | EPOLLERR;
        loop->conn_register(loop, conn);
		conn->on_read = loop->server->on_read;
		conn->on_write = loop->server->on_write;
		conn->on_close = loop->server->on_close;
		conn->write = write_to_buf;
    }
    if(events & EPOLLERR){
        logerror("listen fd error: errno=%d", errno);
		exit(EXIT_FAILURE);
    }
}

static void conn_handler(pIOLoop loop, Conn* conn, int events, int signal){
    long rn = 0, wb=0;
    int new_events = EPOLLERR | EPOLLET, fd = conn->fd;
    
    // event handle
    if(events & EPOLLERR){
		logerror("fd %d error: errno=%d", fd, errno);
		close_conn(loop, conn);
		return;
	}
    if(events & EPOLLIN){
		rn = read_conn(loop, conn);
		//printf("[read %ld from fd %d\n", rn, conn->fd);
		if(rn > 0){
			conn->on_read(conn);
		}else{
			close_conn(loop, conn);
			return;
		}
			
	}
    if(events & EPOLLOUT){
		size_t nw = write_conn(loop, conn);
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

static void conn_modregister(pIOLoop loop, Conn* conn){
    struct epoll_event ev;
	ev.events = conn->events;
	ev.data.ptr = (void*)conn;
	if(epoll_ctl(loop->efd, EPOLL_CTL_MOD, conn->fd, &ev) < 0 ){
		logwarn("fail to mod fd");
		return;
	}
}

static void conn_unregister(pIOLoop loop, Conn* conn){
    int fd = conn->fd;
	epoll_ctl(loop->efd, EPOLL_CTL_DEL, fd, NULL);
	loop->fd_count--;
}

static void conn_register(pIOLoop loop, Conn* conn){
    struct epoll_event ev;
	FD fd = conn->fd;

	ev.data.ptr = (void*)conn;
	ev.events = conn->events;

	if(epoll_ctl(loop->efd, EPOLL_CTL_ADD, fd, &ev) < 0 ){
		logwarn("fail to register FD %d with events %d to epoll", fd, conn->events);
		dealloc_conn(conn);
		return;
	}
	loop->fd_count++;
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
		cb(timer->vars, 0);
        dequeFreeEntry(loop->ready, entry);
	}
}

static FD _create_bind(in_addr_t addr, unsigned short port){
    FD listen_fd;
    struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(addr);
    saddr.sin_port = htons(port);
    if( (listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
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

static int server_start(Server* server){
    server->listenfd = _create_bind(server->addr, server->port);
    if(server->listenfd == -1){
        return -1;
    }
	if(setsockopt(server->listenfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
		logerror("set REUSE_ADDR to listen fd error: %d", errno);
		return -1;
	}

    if(listen(server->listenfd, server->backlog) == -1){
		logerror("listen port %d error: errno=%d", server->port, errno);
		return -1;
	}
    server->_sconn = (Conn*)malloc(sizeof(Conn));
    if(server->_sconn == NULL){
        return -1;
    }
    server->_sconn->fd = server->listenfd;
    server->_sconn->events = EPOLLIN | EPOLLERR | EPOLLET;

    loginfo("listen port %d", server->port);
    ioloop.server = server;
}

static Server* server_bind(Server* server, in_addr_t addr, unsigned short port){
    server->addr = addr;
    server->port = port;
    return server;
}

static Server* server_listen(Server* server, unsigned short backlog){
    server->backlog = backlog;
    return server;
}

Server* new_server(onfunc on_read, onfunc on_write, onfunc on_close){
    Server* server = (Server*)malloc(sizeof(Server));
    if(server == NULL){
        logerror("Out of memory when create new server");
        exit(EXIT_FAILURE);
    }
    server->start = server_start;
    server->bind = server_bind;
    server->listen = server_listen;
	server->on_read = on_read;
	server->on_write = on_write;
	server->on_close = on_close;
    return server;
}

void dealloc_server(Server* server){
    if(server->_sconn){
        free(server->_sconn);
    }
    free(server);
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
    ioloop.conn_handler = conn_handler;
    ioloop.listen_handler = listen_handler;
    ioloop.serve_once = serve_once;
    ioloop.add_timer = add_timer;
    return &ioloop;
}

void dealloc_ioloop(IOLoop* loop){
    dealloc_deque(ioloop.ready);
    ioloop.ready = NULL;

    dealloc_heap(ioloop.timers);
    ioloop.timers = NULL;

    if(loop->server)
        dealloc_server(loop->server);
        loop->server = NULL;

    loop->initial = 0;
}

#define TEST_TIMER

#ifdef TEST_TIMER

void cb(void* vars, int signal){
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

void on_write(Conn* conn){
	logdebug("all data were written to buffer");
}

void on_close(Conn* conn){
	logdebug("conn closed!");
}

#endif

int main(){
    Server* tcpserver = new_server(on_read, on_write, on_close);
    tcpserver->bind(tcpserver, 0, 28080)->listen(tcpserver, 128);

    if(tcpserver->start(tcpserver) == -1){
        dealloc_server(tcpserver);
        return -1;
    }

    IOLoop* loop = ioloop_current();

    #ifdef TEST_TIMER
	long mask = (1 << 16) - 1;

	for(int i = 0; i< 1000; i ++){
		long delay = rand();
    	test_timer(loop, delay & mask);
	}
	
    #endif
	set_loglevel(LOGLV_INFO);
    loop->serve_forever(loop);
    dealloc_ioloop(loop);
}