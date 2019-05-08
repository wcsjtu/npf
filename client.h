#ifndef _CLIENT_H
#define _CLIENT_H

#include "server.h"
#include "ioloop.h"
#include "sgdefs.h"

typedef Conn UDPClient;
typedef Conn TCPClient;


UDPClient* new_udp_client(const char* addr, unsigned short port, int family);
long udpclient_send(UDPClient* cli, char* buf, size_t len, onfunc on_read);
void udpclient_close(pIOLoop loop, UDPClient* cli);


#endif