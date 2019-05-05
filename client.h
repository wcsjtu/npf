#ifndef _CLIENT_H
#define _CLIENT_H

#include "server.h"
#include "ioloop.h"


void send_udp(Conn* conn, char* buf, size_t len, onfunc on_read);
Conn* new_udp_client(const char* addr, unsigned short port, int family);
void send_udp(Conn* conn, char* buf, size_t len, onfunc on_read);
void close_udp_client(pIOLoop loop, Conn* conn);


#endif