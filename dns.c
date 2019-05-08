
#include "logger.h"
#include "dns.h"
#include "util.h"



pDict dns_cache = NULL;
pDict dns_cache_v6 = NULL;

static const char* DNS_SERVER = "10.246.3.33";
static const unsigned short DNS_PORT = 53;

sds new_sds(size_t sz){
    size_t buflen = sizeof(SDS) + sz + 1;   // 1表示末尾的\0
    SDS* s = (SDS*)malloc(buflen);
    if (s == NULL){
        logwarn("Out of memory when create SDS with size %lu", sz);
        return NULL;
    }
    memset(s, 0, buflen);
    s->sz = sz;
    return (sds)(s->buf);
}

void dealloc_sds(sds s){
    if (s == NULL)
        return;
    SDS* ptr = (SDS*)((char*)s - sizeof(SDS)) ;
    free(ptr);
}

// 新建一个ipstr
ipstr new_ipstr(size_t size){
    IPStr* ip = calloc(sizeof(char), sizeof(IPStr) + sizeof(char) * size);
    if(ip == NULL){
        logwarn("Out of memory when new IPStr with size %lu", size);
        return NULL;
    }
    return ip->val;
}

// 释放ipstr
void dealloc_ipstr(ipstr ip){
    if(ip == NULL)
        return;
    IPStr* obj = _ipstr_TO_IPSTR(ip);
    free(obj);
}


// ===================================================
// dict 类型定义

// {sds: sds}
static void* _dns_kv_dup(void* key){
    size_t sz = SDS_LEN((sds)key);
    sds dup = new_sds(sz);
    if(dup)
        memcpy(dup, key, sz);
    return (void*)dup;
};

static int _dns_key_eq(void* key1, void* key2){
    return strcmp((char*)key1, (char*)key2) == 0 ? 1: 0;
}

static void _dns_key_free(pDictEntry entry, void* key){
    if(key)
        dealloc_sds((sds)key);
}

// val 是个链表类型
static void _dns_val_free(void* val){

    if(val == NULL)
        return;
    IPStr* obj = _ipstr_TO_IPSTR(val);
    IPStr* next = NULL;
    while(obj){
        next = _ipstr_TO_IPSTR(obj->next);
        free(obj);
        obj = next;
    }
}

static DictType dnsDictType = {
    hash,
    _dns_kv_dup,    
    _dns_kv_dup,
    _dns_key_eq,
    _dns_key_free,
    _dns_val_free
};

// 初始化dns 缓存容器, 返回1成功, 0失败
int init_dns_cache(size_t size){
    dns_cache = new_dict(size, &dnsDictType);
    if(dns_cache){
        dns_cache_v6 = new_dict(size, &dnsDictType);
        if(dns_cache_v6 == NULL)
            dealloc_dict(dns_cache);
    }
    return dns_cache && dns_cache_v6? 1 : 0;
}

void dealloc_dns_cache(){
    if(dns_cache)
        dealloc_dict(dns_cache);
    if(dns_cache_v6)
        dealloc_dict(dns_cache_v6);

}

static ipstr _link_two(ipstr left, ipstr right){
    if(!right)
        return left;
    _ipstr_TO_IPSTR(right)->next = left;
    return right;
}


// 构造dns请求包
struct DomainPart{
    unsigned char start;
    unsigned char length;
};

// 返回的req是malloc出来的, 所以用完后记得用dealloc_sds释放内存
sds build_dns_request(const char* hostname, size_t length, unsigned short qtype, unsigned short id){
    char* req = NULL, * res=NULL;
    char end = 0, start = 0, part_len = 0;
    unsigned short qcls = htons(QCLASS_IN);
    qtype = htons(qtype);
    if(length >= MAX_HOST_LENGTH || (req = new_sds(DNS_REQ_SIZE(length))) == NULL){
        logwarn("Out of memory when build dns request with length %lu", length);
        return NULL;
    }
    res = req;

    // build request header
    DNSheader header = INIT_REQ_HEADER(id, DNS_STANDARD_REQ, DNS_REQ_REQUIRED_RECUSION);
    COPY_HEADER_TO_BUF(req, &header);

    // build request body
    while (end <= length){
        if(*(hostname + end) == '.' || end == length){
            part_len = end - start;
            if (part_len >= MAX_DNS_PART_LEN){
                logwarn("length of domain name part exceeds MAX_DNS_PART_LEN");
                free(res);
                return NULL;
            }
            // copy length and domain part to req buffer
            *req = part_len;
            req ++;
            memcpy(req, hostname + start, part_len);
            req += part_len;
            // move cursor
            start = end + 1;
        }
        end ++;
    }

    // copy domain end flag to buffer
    *req = DOMAIN_END;
    req ++;

    // copy request tail
    memcpy(req, &qtype, 2);
    req += 2;
    memcpy(req, &qcls, 2);
    req += 2;
    return res;
}

static int dns_parse_header(Parser* parser){
    if (parser->offset != 0){
        logwarn("header has been parsed");
        return 0;
    }
    char* buf = parser->raw;
    parser->header.id = ntohs( *((unsigned short*)buf) );
    buf += 2;
    char* pheader = (char*)(&(parser->header));
    *(pheader + 2) = *buf;
    buf++;
    *(pheader + 3) = *buf;
    buf++;

    parser->header.query_count = ntohs( *((unsigned short*)buf) );
    buf += 2;

    parser->header.rr_count = ntohs( *((unsigned short*)buf) );
    buf += 2;

    parser->header.authrr_count = ntohs( *((unsigned short*)buf) );
    buf += 2;

    parser->header.addrr_count = ntohs( *((unsigned short*)buf) );
    buf += 2;

    parser->offset += DNS_REQ_HEADER_LEN;
    return 1;
}

// 解析query name, 如果allocmem == 0, 或者失败, 则返回NULL; 否则返回sds表示的name
static sds _dns_parse_query(Parser* parser, int allocmem){
    char* buf = parser->raw ;
    unsigned char up = 0, i = parser->offset, offset = parser->offset, part_index = 0;
    unsigned int j = 0, copied = 0, domain_length =0; 
    sds query = NULL;
    struct DomainPart parts[40] = {0};          // 不能超过40个
    struct DomainPart part = {0, 0};
    if (parser == NULL || buf == NULL){
        logwarn("invalid dns parser. not initilized or has no raw data");
        return 0;
    }
    while(buf[i] != DOMAIN_END){
        unsigned char val = buf[i];     // length or cursor
        if (val >= 0xc0){               // exceed 0xc0, mean it is cursor
            if(i >= offset){
                offset += 2;
            }
            //i = buf[i] - 0xc0;
            i = ntohs(*((unsigned short*)(buf+i))) - 0xc000;
            continue;
        }
        up = i + val + 1;
        parts[part_index] = (struct DomainPart){i + 1, val};
        part_index ++ ;

        domain_length += (val + 1);     //. 要占一位
        if(up >= offset)
            offset += (val + 1);
        i = up;
    }
    if (up >= offset)
        offset += 1;

    // copy query name to buffer
    if(domain_length <= 1){
        logwarn("bad hostname whose length <= 1");
        return NULL;
    }
    domain_length -- ;                  // 上面多加了一个.

    if(allocmem){   // 需要分配内存的话
        if((query=new_sds(domain_length)) == NULL){
            logwarn("Out of memory when parse dns query name");
            return NULL;
        }
        for(; j < part_index; j++){
            part = parts[j];
            memcpy(query + copied, buf + part.start, part.length);
            copied += part.length;
            if (j != part_index - 1){
                *(query + copied) = '.';
                copied ++;
            }
        }
    }
    parser->offset = offset;    // 解析成功后, 才更新offset
    return query;
}

#define _SHORT_FROM_PARSER(parser, v) v = ntohs( *((unsigned short*)(parser->raw + parser->offset)) );\
    parser->offset += 2

#define _INT_FROM_PARSER(parser, v) v = ntohl(*((unsigned int*)(parser->raw + parser->offset)));\
    parser->offset += 4

static ipstr __dns_parse_rrs(Parser* parser, int eqt, size_t n){
    if(n == 0)
        return NULL;
    char* buf = parser->raw;
    unsigned short qtype = 0, qcls = 0, data_length = 0;
    unsigned int ttl = 0;
    ipstr ip = NULL, next = NULL;

    for(size_t i = 0; i< n; i++){
        _dns_parse_query(parser, 0);
        
        _SHORT_FROM_PARSER(parser, qtype);
        _SHORT_FROM_PARSER(parser, qcls);
        _INT_FROM_PARSER(parser, ttl);
        _SHORT_FROM_PARSER(parser, data_length);

        switch (qtype) 
        {
        case QTYPE_A:
            if(qtype != eqt){
                logwarn("DNS response with error qtye");
                parser->offset += data_length;
            } else{
                next = new_ipstr(INET_ADDRSTRLEN + 1);    // TODO 没有做OOM校验
                inet_ntop(AF_INET, buf + parser->offset, next, INET_ADDRSTRLEN);  // TODO 没做合法性校验
                // 组合链表
                ip = _link_two(ip, next);
            }
            parser->offset += data_length;
            break;
        case QTYPE_AAAA:
            if(qtype != eqt){
                logwarn("DNS response with error qtye");
                parser->offset += data_length;
            } else{
                next = new_ipstr(INET6_ADDRSTRLEN + 1);    // TODO 没有做OOM校验
                inet_ntop(AF_INET6, buf + parser->offset, next, INET6_ADDRSTRLEN); // TODO 没做合法性校验
                // 组合链表
                ip = _link_two(ip, next);
            }
            parser->offset += data_length;
            break;
        default:    // cname的情况
            _dns_parse_query(parser, 0);
            break;
        }
    }
    return ip;
}

// 容器是malloc出来的, 用完记得用dealloc_iplist来释放内存
ipstr dns_parse_response(pParser parser){
    sds query = NULL;
    ipstr res = NULL;
    unsigned short qtype, qcls;
    if(!parser || parser->offset != 0){
        logwarn("invalid parser, NULL or parsed");
        return NULL;
    }

    if(!dns_parse_header(parser)){
        logwarn("dns header parse failed");
        return NULL;
    }
    query = _dns_parse_query(parser, 1);
    if(!query){
        logwarn("dns query name parse failed");
        return NULL;
    }

    _SHORT_FROM_PARSER(parser, qtype);
    _SHORT_FROM_PARSER(parser, qcls);

    if(parser->header.rr_count)
        res = __dns_parse_rrs(parser, qtype, parser->header.rr_count);
    if(parser->header.authrr_count)
        res = _link_two(res, __dns_parse_rrs(parser, qtype, parser->header.authrr_count)) ;
    if(parser->header.addrr_count)
        res = _link_two(res, __dns_parse_rrs(parser, qtype, parser->header.addrr_count)) ;

    pDict cache = qtype == QTYPE_A ? dns_cache : dns_cache_v6;
    set_item(cache, query, res);
    return res;
}

// parser是malloc出来的, 用完记得用dealloc_dnsparser释放
pParser new_dns_parser(char* raw, size_t length){
    pParser parser = NULL;
    if ((parser = malloc(sizeof(Parser))) == NULL){
        logwarn("Out of memory when create dns parser");
        return NULL;
    }
    memset(parser, 0, sizeof(Parser));
    parser->raw = raw;
    parser->length = length;
    return parser;
}

void dealloc_dnsparser(pParser parser){
    if(parser)
        free(parser);
}

static void _on_dns_response(UDPClient* cli){
    RBSeg seg;
    ipstr ip;
    handler cb =  (handler)(cli->extra);
    if(!rb_readable(cli->rbuf, &seg)){
        cb(NULL, SG_INTERN_ERR);
        return;
    }
    pParser parser =  new_dns_parser(seg.buf, seg.len);
    ip = dns_parse_response(parser);
    dealloc_dnsparser(parser);
    udpclient_close(ioloop_current(), cli);
    cb(ip,  ip ? SG_OK : SG_INTERN_ERR);
    cli->extra = NULL;      // 清空
}

void resolve(const char* hostname, int family, handler callback){
    int qtype = family == AF_INET ? QTYPE_A : QTYPE_AAAA;
    sds req = build_dns_request(hostname, strlen(hostname), qtype, (short)rand());
    if(!req){
        callback(NULL, SG_OUTOFMEM);
        return ;
    }
    UDPClient* cli = new_udp_client(DNS_SERVER, DNS_PORT, family);
    if(!cli){
        callback(NULL, SG_OUTOFMEM);
        return ;
    }
    cli->extra = (void*)callback;
    udpclient_send(cli, req, SDS_LEN(req), _on_dns_response);
    dealloc_sds(req);
}



//#define TEST_DNS

#ifdef TEST_DNS

char ipv6_response[] = { /* Packet 1912 */
0xc7, 0xfb, 0x81, 0x80, 0x00, 0x01, 0x00, 0x05, 
0x00, 0x00, 0x00, 0x00, 0x09, 0x73, 0x75, 0x62, 
0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x06, 0x6f, 
0x66, 0x66, 0x69, 0x63, 0x65, 0x03, 0x63, 0x6f, 
0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 
0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 
0x00, 0x14, 0x09, 0x73, 0x75, 0x62, 0x73, 0x74, 
0x72, 0x61, 0x74, 0x65, 0x07, 0x6d, 0x73, 0x2d, 
0x61, 0x63, 0x64, 0x63, 0xc0, 0x16, 0xc0, 0x32, 
0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 
0x00, 0x08, 0x05, 0x61, 0x66, 0x64, 0x2d, 0x6b, 
0xc0, 0x16, 0xc0, 0x52, 0x00, 0x05, 0x00, 0x01, 
0x00, 0x00, 0x00, 0x25, 0x00, 0x28, 0x12, 0x6f, 
0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b, 0x2d, 0x6f, 
0x66, 0x66, 0x69, 0x63, 0x65, 0x2d, 0x63, 0x6f, 
0x6d, 0x06, 0x6b, 0x2d, 0x30, 0x30, 0x30, 0x32, 
0x08, 0x6b, 0x2d, 0x6d, 0x73, 0x65, 0x64, 0x67, 
0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x66, 
0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7a, 
0x00, 0x02, 0xc0, 0x79, 0xc0, 0x9a, 0x00, 0x1c, 
0x00, 0x01, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x10, 
0x26, 0x20, 0x01, 0xec, 0x00, 0x0c, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11 };

char peer1_0[] = { /* Packet 2541 */
0x83, 0xec, 0x81, 0x80, 0x00, 0x01, 0x00, 0x05, 
0x00, 0x00, 0x00, 0x00, 0x09, 0x73, 0x75, 0x62, 
0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x06, 0x6f, 
0x66, 0x66, 0x69, 0x63, 0x65, 0x03, 0x63, 0x6f, 
0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 
0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1f, 
0x00, 0x14, 0x09, 0x73, 0x75, 0x62, 0x73, 0x74, 
0x72, 0x61, 0x74, 0x65, 0x07, 0x6d, 0x73, 0x2d, 
0x61, 0x63, 0x64, 0x63, 0xc0, 0x16, 0xc0, 0x32, 
0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1f, 
0x00, 0x08, 0x05, 0x61, 0x66, 0x64, 0x2d, 0x6b, 
0xc0, 0x16, 0xc0, 0x52, 0x00, 0x05, 0x00, 0x01, 
0x00, 0x00, 0x00, 0x1f, 0x00, 0x28, 0x12, 0x6f, 
0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b, 0x2d, 0x6f, 
0x66, 0x66, 0x69, 0x63, 0x65, 0x2d, 0x63, 0x6f, 
0x6d, 0x06, 0x6b, 0x2d, 0x30, 0x30, 0x30, 0x32, 
0x08, 0x6b, 0x2d, 0x6d, 0x73, 0x65, 0x64, 0x67, 
0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x66, 
0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 
0x00, 0x02, 0xc0, 0x79, 0xc0, 0x9a, 0x00, 0x01, 
0x00, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 
0x0d, 0x6b, 0x12, 0x0b };

// char peer1_0[] = { /* Packet 26 */
// 0x5a, 0x07, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 
// 0x00, 0x00, 0x00, 0x00, 0x06, 0x63, 0x6f, 0x6e, 
// 0x66, 0x69, 0x67, 0x06, 0x70, 0x69, 0x6e, 0x79, 
// 0x69, 0x6e, 0x05, 0x73, 0x6f, 0x67, 0x6f, 0x75, 
// 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 
// 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0x93, 
// 0x23, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0xdc, 0xb5, 0x7c, 
// 0x24, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0xab, 
// 0x28, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0xab, 
// 0x2b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0x6a, 0x27, 0xf6, 
// 0x2b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0x6a, 0x27, 0xf6, 
// 0x29, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0x93, 
// 0x24, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x03, 0x00, 0x04, 0xdc, 0xb5, 0x7c, 
// 0x32 };


int main(){

    pParser parser = new_dns_parser(ipv6_response, 23 * 8);
    IPlist res = dns_parse_response(parser);
    ipaddr ip;
    
    size_t sz = IPLIST_SIZE(res);
    for(size_t i = 0; i< IPLIST_SIZE(res); i ++){
        ip = res[i];
        unsigned short qtype = IPADDR_QTYPE(ip);
        logdebug("%s", ip);
    }
    return 0;
}

#endif


