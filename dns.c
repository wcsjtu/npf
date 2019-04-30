
#include "logger.h"
#include "dns.h"
#include "util.h"

//static char DNS_REQ_HEADER[] = {1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };

sds new_sds(size_t sz){
    SDS* s = (SDS*)malloc(sizeof(SDS) + sz);
    if (s == NULL){
        logwarn("Out of memory when create SDS with size %lu", sz);
        return NULL;
    }
    s->sz = sz;
    return (sds)(s->buf);
}

void dealloc_sds(sds s){
    if (s == NULL)
        return;
    free(s - sizeof(SDS));
}

ipaddr new_ipaddr(sds domain, unsigned char qt, unsigned char sz){
    pRR rr = (pRR)malloc(sizeof(RR) + sz);
    if (rr == NULL){
        logwarn("Out of memory when create new IPADDR");
        return NULL;
    }
    rr->qtype = qt;
    rr->sz = sz;
    rr->domain = domain;
    return rr->addr;
}

void dealloc_ipaddr(ipaddr addr){
    pRR rr = (pRR)(addr - sizeof(RR));
    dealloc_sds( rr->domain );
    free(rr);
}



// 构造dns请求包
struct DomainPart{
    unsigned char start;
    unsigned char length;
};

char* build_dns_request(const char* hostname, size_t length, unsigned short qtype, unsigned short id){
    char* req = NULL, * res=NULL;
    char end = 0, start = 0, part_len = 0;
    unsigned short qcls = htons(QCLASS_IN);
    qtype = htons(qtype);
    if(length >= MAX_HOST_LENGTH || (req = malloc( DNS_REQ_SIZE(length))) == NULL){
        logwarn("Out of memory when build dns request with length %lu", length);
        return NULL;
    }
    res = req;

    // build request header
    DNSheader header = INIT_REQ_HEADER(id, DNS_STANDARD_REQ, DNS_REQ_REQUIRED_RECUSION);
    COPY_HEADER_TO_BUF(req, &header);

    // build request body
    while (end <= length){
        if(hostname[end] == '.' || end == length){
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

static sds dns_parse_query(Parser* parser){
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
    domain_length -- ;                  // 上面多加了一个.
    if (up >= offset)
        offset += 1;

    // copy query name to buffer
    if(domain_length <= 1){
        logwarn("bad hostname whose length <= 1");
        return 0;
    }
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
    parser->offset = offset;    // 解析成功后, 才更新offset
    return query;
}

#define _SHORT_FROM_PARSER(parser, v) v = ntohs( *((unsigned short*)(parser->raw + parser->offset)) );\
    parser->offset += 2

#define _INT_FROM_PARSER(parser, v) v = ntohl(*((unsigned int*)(parser->raw + parser->offset)));\
    parser->offset += 4

static void __dns_parse_rrs(Parser* parser, ipaddr* list, size_t n){
    if(n == 0)
        return ;
    char* buf = parser->raw;
    sds query = NULL, cname = NULL;
    unsigned short qtype = 0, qcls = 0, data_length = 0;
    unsigned int ttl = 0;
    int af = 0;

    ipaddr addr = NULL;

    for(size_t i = 0; i< n; i++){
        query = dns_parse_query(parser);
        if(query == NULL)
            return;
        _SHORT_FROM_PARSER(parser, qtype);
        _SHORT_FROM_PARSER(parser, qcls);
        _INT_FROM_PARSER(parser, ttl);
        _SHORT_FROM_PARSER(parser, data_length);

        switch (qtype) 
        {
        case QTYPE_A:
            addr = new_ipaddr(query, QTYPE_A, INET_ADDRSTRLEN + 1);     // TODO 没有做OOM校验
            inet_ntop(AF_INET, buf + parser->offset, addr, INET_ADDRSTRLEN);
            break;
        case QTYPE_AAAA:
            addr = new_ipaddr(query, QTYPE_A, INET6_ADDRSTRLEN + 1);
            inet_ntop(AF_INET6, buf + parser->offset, addr, INET6_ADDRSTRLEN);
            break;
        default:
            logdebug("qtype == %d", qtype);
            addr = new_ipaddr(query, qtype, data_length);
            cname = dns_parse_query(parser);
            if (cname){
                memcpy(addr, cname, SDS_LEN(cname));
                dealloc_sds(cname);
            }
            break;
        }
        parser->offset += data_length;
        *list = addr;
        list++;
    }
    return;
}


ipaddr* dns_parse_response(pParser parser){
    sds query = NULL;
    size_t rrs = 0;
    unsigned short qtype, qcls;
    if(!parser || parser->offset != 0){
        logwarn("invalid parser, NULL or parsed");
        return NULL;
    }

    if(!dns_parse_header(parser)){
        logwarn("dns header parse failed");
        return NULL;
    }
    rrs = parser->header.addrr_count + parser->header.authrr_count + parser->header.rr_count;
    query = dns_parse_query(parser);
    if(!query){
        logwarn("dns query name parse failed");
        return NULL;
    }
    ipaddr* list = (ipaddr*)malloc(sizeof(ipaddr)*rrs);
    if(!list){
        logwarn("create new ipaddr list with size %lu failed", rrs);
        dealloc_sds(query);
        return NULL;
    }
    _SHORT_FROM_PARSER(parser, qtype);
    _SHORT_FROM_PARSER(parser, qcls);

    if(parser->header.rr_count)
        __dns_parse_rrs(parser, list, parser->header.rr_count);
    if(parser->header.authrr_count)
        __dns_parse_rrs(parser, list, parser->header.authrr_count);
    if(parser->header.addrr_count)
        __dns_parse_rrs(parser, list, parser->header.addrr_count);
    dealloc_sds(query);     // TODO 直接把域名释放了, 是不是不太好
    return list;
}



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


#define TEST_DNS

#ifdef TEST_DNS

char peer1_0[] = { /* Packet 26 */
0x5a, 0x07, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 
0x00, 0x00, 0x00, 0x00, 0x06, 0x63, 0x6f, 0x6e, 
0x66, 0x69, 0x67, 0x06, 0x70, 0x69, 0x6e, 0x79, 
0x69, 0x6e, 0x05, 0x73, 0x6f, 0x67, 0x6f, 0x75, 
0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 
0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0x93, 
0x23, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0xdc, 0xb5, 0x7c, 
0x24, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0xab, 
0x28, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0xab, 
0x2b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0x6a, 0x27, 0xf6, 
0x2b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0x6a, 0x27, 0xf6, 
0x29, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0x24, 0x6e, 0x93, 
0x24, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
0x00, 0x00, 0x03, 0x00, 0x04, 0xdc, 0xb5, 0x7c, 
0x32 };

int main(){

    pParser parser = new_dns_parser(peer1_0, 21 * 8 + 1);
    ipaddr* res = dns_parse_response(parser);

    return 0;
}

#endif

