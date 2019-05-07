#ifndef _DNS_H
#define _DNS_H
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "dict.h"

typedef struct _sds{
    size_t sz;
    char buf[];
} SDS;

typedef char* sds;

sds new_sds(size_t sz);
void dealloc_sds(sds s);

#define SDS_LEN(s) ( ((SDS*)((char*)(s) - sizeof(SDS)))->sz )

/*

DNS header structure

0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15   16
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
|                             request id                                        |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
| QR |      opcode       | AA | TC | RD | RA |      0       |        rcode      |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
|                                 query count                                   |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
|                          resource recode(RR) count                            |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
|                   authoritative resource recode(RR) count                     |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
|                    additional resource recode(RR) count                       |
+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
|                          query name(variable length) ....

request id: 16 bits 随机数
QR:         1 bit. 0表示查询报文, 1表示响应报文
opcode:     4 bits. 标准查询(0)、反向查询(1)、服务器状态请求(2)
AA:         1 bit. Authoritative Answer, 表示`授权回答`
TC:         1 bit. 表示可截断的, 如果UDP报文长度超过512字节, 则只返回前512字节
RD:         1 bit. Recursion Desired. 期望递归. 如果在请求报文中设置该位, 则表示服务器必须回答;
                否则, 在服务器没有授权时, 服务器会返回一个能回答的服务器列表
RA:         1 bit. Recursion Avaliable. 出现在响应报文中, 表示服务器支持递归查询
rcode:      4 bits. 状态码, 没有差错(0)、名字差错(3)。名字差错只能从授权的服务器上返回, 表示域名不存在

query count: 16 bits. 查询的问题数, 一般在查询报文中设置
AN count:    16 bits. 回复的记录数, 一般在响应报文中设置
NS count:    16 bits. 
AR count:    16 bits. 


DNS query name structure

+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 3 | w   w   w | 5 | b   a   i   d   u | 3 | c   o   m | 0 |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
前面的数字是后面part的长度, 不能超过63. 末尾的0表示结束符


DNS resource record(RR) structure

0                            15                             31
+----+----+----+----+----+----+----+----+----+----+----+----+
.                                                           .
.                       domain name                         .
.                                                           .
+----+----+----+----+----+----+----+----+----+----+----+----+
|          query type         |        query class          |
+----+----+----+----+----+----+----+----+----+----+----+----+
|                            TTL                            |
+----+----+----+----+----+----+----+----+----+----+----+----+
|         data length         |             data            .
.
.

query class:    16 bit. 查询类, 通常是1, 表示互联网地址
TTL:            32 bits. 客户端程序应该保留该记录的秒数
data length:    16 bits. 资源数据的长度
data:           变长。 长度由data length 指定。 其格式与query type 有关
query type:     16 bits. 查询类型。每个问题都有一个查询类型。 每个回答也有查询类型, 具体含义见下表

名字        值              描述
A           1           ipv4地址
AAAA        28          ipv6地址
NS          2           名字服务器
CNAME       5           规范名称
PTR         12          指针记录
HINFO       13          主机信息
MX          15          邮件交换记录
AXFR        252         
ANY         255


*/

typedef struct _dnsheader{
    unsigned short id;

    // 因为地址增长方向相反, 所以只能把字段定义倒过来
    unsigned char rd          : 1;
    unsigned char tc          : 1;
    unsigned char aa          : 1;
    unsigned char opcode      : 4;
    unsigned char qr          : 1;      // qr在协议里是高位, 所以必须定义在下面
    
    unsigned char rcode       : 4;
    unsigned char reserved    : 3;
    unsigned char ra          : 1;
    
    
    unsigned short query_count;
    unsigned short rr_count;
    unsigned short authrr_count;
    unsigned short addrr_count;
} DNSheader;

#define INIT_REQ_HEADER(id, op, rd) {id, rd, 0, 0, op, 0,  0, 0, 0, 1, 0, 0, 0} 

#define COPY_HEADER_TO_BUF(buf, phdr) do {\
    unsigned short tmp = htons((phdr)->id); memcpy(buf, &tmp, 2); buf+=2;\
    *buf = (*((char*)(phdr) + 2)); buf++;\
    *buf = (*((char*)(phdr) + 3)); buf++;\
    tmp = htons((phdr)->query_count);  memcpy(buf, &tmp, 2); buf+=2;\
    tmp = htons((phdr)->rr_count);  memcpy(buf, &tmp, 2); buf+=2;\
    tmp = htons((phdr)->authrr_count);  memcpy(buf, &tmp, 2); buf+=2;\
    tmp = htons((phdr)->addrr_count);  memcpy(buf, &tmp, 2); buf+=2;\
    } while(0)


typedef struct  _parser{
    size_t length;
    unsigned int offset;
    DNSheader header;
    char* raw;
} Parser, *pParser;

#define DNS_REQ_REQUIRED_RECUSION 1
#define DNS_STANDARD_REQ 0

#define DOMAIN_END 0x00
#define DNS_REQ_HEADER_LEN 12
#define DNS_REQ_TAIL_LEN 5
#define MAX_DNS_PART_LEN 63

#define QTYPE_A 1
#define QTYPE_NS 2
#define QTYPE_CNAME 5
#define QTYPE_AAAA 28
#define QTYPE_ANY 255
#define QCLASS_IN 1

#define MAX_HOST_LENGTH 255

#define DNS_REQ_SIZE(host_length) (DNS_REQ_HEADER_LEN + \
	DNS_REQ_TAIL_LEN + (host_length) + 1)	//n个点对应着n+1段的长度, 再加上\x00结束符


sds build_dns_request(const char* hostname, size_t length, unsigned short qtype, unsigned short id);

pParser new_dns_parser(char* raw, size_t length);
void dealloc_dnsparser(pParser parser);



int init_dns_cache(size_t size);
void dealloc_dns_cache();

typedef char* ipstr;

typedef struct _ipstr{
    ipstr next;
    size_t size;
    char val[];
} IPStr;

// 将字符串形式的ipstr, 转为IPStr实例
#define _ipstr_TO_IPSTR(ip)  ( (IPStr*)( (char*)(ip) - sizeof(IPStr)) )

// 获取ipstr的长度
#define IPSTR_LEN(ip) ( _ipstr_TO_IPSTR(ip)->size )

// 获取下一个IP
#define IPSTR_NEXT(ip)  ( _ipstr_TO_IPSTR(ip)->next)

ipstr dns_parse_response(Parser* parser);

#endif