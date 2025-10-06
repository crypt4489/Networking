#pragma once

#include <cstdint>
#include <winsock2.h>


enum RCODE
{
	RCODE_NOERROR = 0,
	RCODE_FORMATERROR = 1,
	RCODE_SERVFAIL = 2,
	RCODE_NXDOMAIN = 3,
	RCODE_NOTIMPLEMENTED = 4,
	RCODE_REFUSED = 5
};


#pragma pack(push, 1)
typedef struct dns_header_t
{
	uint16_t ID;
	
	uint16_t flags;
	
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t NSCOUNT;
	uint16_t ARCOUNT;
} DNSHeader;


static_assert(sizeof(dns_header_t) == 12, "DNS Header not packs");

typedef struct dns_question_t
{
	uint16_t QTYPE;
	uint16_t QCLASS;
} DNSQuestion;

enum AnsTYPE
{
	A = 1,
	NS = 2,
	MD = 3, //obsolete
	MF = 4,
	CNAME = 5,
	SOA = 6,
	MX = 15,
	AAAA = 28
};

typedef struct dns_answer_t
{
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
} DNSAnswer;

static_assert(sizeof(dns_answer_t) == 10, "dns answer not packed");

#pragma pack(pop) 

typedef struct dns_packet_t
{
	DNSHeader header;
	DNSQuestion query;
} DNSQueryPacket;

typedef struct dns_answer_packet_t
{
	DNSHeader Header;
	DNSAnswer Answer;
} DNSAnswerPacket;

char* GetAddrByHostName(sockaddr_in* s, const char* str, int flags);

