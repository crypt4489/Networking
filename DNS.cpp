#include "DNS.h"

#include <stdio.h>
#include <ws2tcpip.h>
#include <sysinfoapi.h>
#include <stdlib.h>
#include <limits.h>

#define DEFAULT_DNS_PORT 53
#define CACHE_LINE  64
#define CACHE_ALIGN __declspec(align(CACHE_LINE))

#define MAX_USHORT (uint16_t)~0ui16

#define QUERYHOSTNAME MAX_USHORT


#define ERROR_LOG_LVL 1
#define DEBUG_LOG_LVL 2
#define INFO_LOG_LVL 3

#define DNS_LOG_LVL 0

#define STRINGIFY_IMPL(X) #X
#define STRINGIFY(X) STRINGIFY_IMPL(X)

#if defined(INFO_LOG_LVL) && DNS_LOG_LVL >= INFO_LOG_LVL
#define INFOLOG(fmt, ...) \
        (printf("INFO : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else 
#define INFOLOG(fmt, ...)
#endif

#if defined(DEBUG_LOG_LVL) && DNS_LOG_LVL >= DEBUG_LOG_LVL
#define DEBUGLOG(fmt, ...)  \
        (printf("DEBUG : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else
#define DEBUGLOG(fmt, ...)
#endif


#if  defined(ERROR_LOG_LVL) && DNS_LOG_LVL >= ERROR_LOG_LVL
#define ERRORLOG(fmt, ...) \
        (printf("ERROR : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else
#define ERRORLOG(fmt, ...)
#endif

#define MAX_STRING_LEN 256
#define COPYSTRING(src, dest, count) \
	do { \
		dest[count] = src[count]; \
	} while(src[count++] && count < MAX_STRING_LEN) \


enum DNSReturnCodes
{
	NODOMAIN = 0,
	SERVERFAILURE = -1,
};


typedef struct dns_record_reference
{
	uint16_t type;
	uint16_t offset;
	void* packet;
	uint32_t size;
	uint32_t visited;
} DNSRecordReference;

typedef struct dns_answer_a
{
	uint16_t referenceHostNameRecordID;
	uint32_t addr;
} DNSARecord;

typedef struct dns_answer_aaaa
{
	uint16_t referenceHostNameRecordID;
	char addr[16];
	char pad[6];
}DNSAAAARecord;

typedef struct dns_answer_cname {
	uint16_t namelength;
	uint16_t arecordcount;
	uint16_t arecordid[10];
	uint32_t queryAlias;
	uint32_t pad;
} DNSCNAMERecord;

typedef struct dns_answer_ns {
	uint16_t namelength;
	uint16_t arecordcount;
	uint16_t arecordid[10];
	uint32_t queryAlias;
	uint32_t pad;
} DNSNSRecord;

typedef struct dns_answer_mx {
	uint16_t preference;
	uint16_t namelength;
	uint16_t arecordcount;
	uint16_t arecordid[10];
	uint32_t queryAlias;
	uint16_t pad;
} DNSMXRecord;

typedef struct dns_pointer_struct
{
	uint16_t recordOffset;
	uint16_t dnsReferenceRecordOffset;
	uint16_t internalRecordBufferOffset;
} DNSPointer;

#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB

#define DNSANSPOOLSIZE 512*KB
#define DNSQUERYPOOLSIZE 256*KB
#define FUNCANSWEPOOL 2 * MB
#define RECORDPOOLSIZE 256*KB


static CACHE_ALIGN char QueryPool[DNSQUERYPOOLSIZE];
static int QueryCount = 0;
static CACHE_ALIGN char DNSAnswerPool[DNSANSPOOLSIZE];
static int DNSAnswerCount = 0;

static CACHE_ALIGN char RecordsBuffer[RECORDPOOLSIZE];
static int RecordsBufferCounter = 0;
static int RecordsBufferReader = 0;

static CACHE_ALIGN char HelperSpace[128];

static CACHE_ALIGN char FunctionAnswerPool[FUNCANSWEPOOL];
static int FunctionAnswerPtr = 0;

#define MAX_RECURSE_LIMIT 10

static CACHE_ALIGN int RecursionLevelPointers[MAX_RECURSE_LIMIT];
static CACHE_ALIGN int RecursionLevelEnds[MAX_RECURSE_LIMIT];
static int RecursionLevelPointer = 0;

static uint16_t make_dns_flags(int QR, int OpCode, int AA, int TC, int RD, int RA, int Z, int RCODE)
{
	uint16_t ret = 0;

	ret =
		(QR & 1) << 15 |
		(OpCode & 0xf) << 11 |
		(AA & 1) << 10 |
		(TC & 1) << 9 |
		(RD & 1) << 8 |
		(RA & 1) << 7 |
		(Z & 7) << 4 |
		(RCODE & 0xf) << 0;

	return ret;
}

static void print_dns_flags(uint16_t flags)
{
	DEBUGLOG("QR=%d ", (flags >> 15) & 0x1);
	DEBUGLOG("OpCode=%d ", (flags >> 11) & 0xF);
	DEBUGLOG("AA=%d ", (flags >> 10) & 0x1);
	DEBUGLOG("TC=%d ", (flags >> 9) & 0x1);
	DEBUGLOG("RD=%d ", (flags >> 8) & 0x1);
	DEBUGLOG("RA=%d ", (flags >> 7) & 0x1);
	DEBUGLOG("Z=%d ", (flags >> 4) & 0x7);
	DEBUGLOG("RCODE=%d", (flags >> 0) & 0xF);
}

static int CreateQueryHostname(const char* hostname, char* output)
{
	int stride = 0;

	if (!hostname || !output)
		return stride;
	
	const char* ptr = hostname;
	char* outputAddr = output;

	while (*ptr)
	{
		char count = 0;
		const char* copy = ptr;
		char* inSertCount = outputAddr;
		outputAddr++;
		while (*ptr != '.' && *ptr != '\0')
		{
			*outputAddr = *ptr;
			count++;
			ptr++;
			outputAddr++;
		}
		
		if (count) {
			ptr++;
			*inSertCount = count;
			stride += (count + 1);
		}
	}
	outputAddr[0] = 0;

	return stride + 1;
};

static int dumpstring(char* c, char count, int terminate)
{
#if DNS_LOG_LVL >= 2
	int i = 0;
	while (count-- > 0)
	{
		printf("%c", *c);
		c++;
		i++;
		if (!count && terminate > 0) {
			printf(".");
		}
	} 
	return i;
#else
	return 0;
#endif
}

static int writestring(char* c, char count, int terminate, char *write)
{
	int i = 0;
	while (count-- > 0)
	{
		*write++ = *c++;
		i++;
	}
	
	if (terminate) {
		*write++ = '.';
		i++;
	}
	else {
		*write++ = '\0';
		i++;
	}


	return i;
}

static int PrintHostName(char* str, char *queryHead, int recursionCount)
{
#if DNS_LOG_LVL >= 2
	if (recursionCount >= 255) return -1;
	int i = 0;
	char* iter = str;
	char count;
	while (++i && (count = *iter++))
	{

		if (count < 0)
		{
			uint16_t offsetp = (((uint16_t)count) << 8) | (iter[0] & 0xff);

			i++;
			iter++;
			printf(".");
			
			if (offsetp & 0xC000)
			{
				offsetp &= 0x3FFF;
				iter = (queryHead + offsetp);
				int rem = PrintHostName(iter, queryHead, recursionCount++);

				if (rem < 0) return rem;
			}
			break;
		} 
		


		char* stub = iter + count;

		int rem = dumpstring(iter, count, (int)stub[0]);
			
		i += rem;
		iter += rem;

		
	}
	if (!recursionCount) {
		printf("\n");
	}
	return i;

#else

	return 0;
#endif
}

static int WriteHostName(char* str, char* queryHead, int recursionCount, char *write)
{

	if (recursionCount >= 255) return -1;
	int i = 0;
	char* iter = str;
	char count;
	while (count = *iter++)
	{

		if (count < 0)
		{
			uint16_t offsetp = (((uint16_t)count) << 8) | (iter[0] & 0xff);

			iter++;

			if (offsetp & 0xC000)
			{
				offsetp &= 0x3FFF;

				iter = (queryHead + offsetp);

				int rem = WriteHostName(iter, queryHead, recursionCount++, write);

				if (rem < 0) return rem;

				i += rem;
			}
			break;
		}

		char* stub = iter + count;

		int rem = writestring(iter, count, (int)stub[0], write);

		i += rem;
		iter += (rem-1);
		write += rem;
	}

	return i+1;
}

static int HandleDNSAnswer(DNSAnswer* answer, char* queryHead, DNSPointer* pointer);

static int HandleDNSNSNames(DNSAnswer* answer, char* queryHead, DNSPointer* pointer);

static int HandlePointerCondition(uint16_t* iter, DNSPointer* pointer);

static int HandleDNSAdditional(DNSAnswer* answer, char* queryHead, DNSPointer* pointer);

static int ProcessBuffer(DNSQueryResult* resultSpace);

static void PrintIPv4(uint32_t addr);

static void PrintIPv6(char* addr);

static void PrintRecordHostname(char* ptr);

static int DeDeuplicateIPv4(char* recordBuffer, uint16_t count, uint16_t* recordoffsets, int addr);

static int DeDeuplicateIPv6(char* recordBuffer, uint16_t count, uint16_t* recordoffsets, char* addr);

static int RecurseFindAddress(int* recordPtr)
{
	int addr = 0, begin = *recordPtr;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[begin];

	if (ref->visited) goto recurse_find_end;

	switch (ref->type)
	{
	case A:
	{
		DNSARecord* record = (DNSARecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		addr = record->addr;

		ref->visited = 1;

		break;
	}
	case CNAME:
	{
		DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		if (record->arecordcount)
		{
			for (uint16_t g = 0; g < record->arecordcount; g++)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

				if (aRef1->visited) continue;

				aRef1->visited = 1;

				DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

				addr = aRef->addr;

				goto recurse_find_end;
			}
		}

		ref->visited = 1;

		break;
	}
	case NS:

	{
		DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		if (record->arecordcount)
		{
			for (uint16_t g = 0; g < record->arecordcount; g++)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

				if (aRef1->visited) continue;

				aRef1->visited = 1;


				if (aRef1->type == A)
				{
					DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

					addr = aRef->addr;

					goto recurse_find_end;
				}
			}	
		}

		ref->visited = 1;

		break;
	}
	case MX:
	{

		DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		if (record->arecordcount)
		{
			for (uint16_t g = 0; g < record->arecordcount; g++)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

				aRef1->visited = 1;

				if (aRef1->type == A)
				{
					DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

					addr = aRef->addr;

					goto recurse_find_end;
				}
			}
		}

		ref->visited = 1;

		break;
	}
	default:
		break;
	}

recurse_find_end:

	if (!addr) *recordPtr += ref->size;

	return addr;
}

static int RecurseDNSResolver(sockaddr_in* dnsResolver, int recordsBufferStart)
{
	int addr = 0;
	int begin = recordsBufferStart;

	if (RecursionLevelPointer+1 < MAX_RECURSE_LIMIT && recordsBufferStart < RecordsBufferCounter) // we have new records
	{
		if (RecursionLevelPointers[++RecursionLevelPointer] == -1)
		{
			while (!addr && begin < RecordsBufferCounter)
			{
				addr = RecurseFindAddress(&begin);	
			}
		}
	}
	
	if (!addr)
	{

		RecursionLevelPointer--;

		while (RecursionLevelPointer >= 0 && (RecursionLevelPointers[RecursionLevelPointer] == RecursionLevelEnds[RecursionLevelPointer]))
		{
			RecursionLevelPointers[RecursionLevelPointer] = -1;
			RecursionLevelPointer--;
		}
		

		while (!addr && RecursionLevelPointer >= 0)
		{

			begin = RecursionLevelPointers[RecursionLevelPointer]; // got a new level;

			addr = RecurseFindAddress(&begin);

			if (!addr)
			{
		
				if (begin == RecursionLevelEnds[RecursionLevelPointer])
				{
					RecursionLevelPointers[RecursionLevelPointer] = -1;
					RecursionLevelPointer--;
				}
				else 
				{
					RecursionLevelPointers[RecursionLevelPointer] = begin;
				}
			}
		}
	}
	else 
	{
		// got a new level;
		RecursionLevelEnds[RecursionLevelPointer] = RecordsBufferCounter;
		RecursionLevelPointers[RecursionLevelPointer] = begin;
	}

	RecordsBufferReader = recordsBufferStart;

	PrintIPv4(addr);

	dnsResolver->sin_addr.s_addr = ntohl(addr);

	return (addr ? 0 : -1);
}


static int CreateDNSQuestion(int flags, const char* domainname)
{
	char* q = QueryPool + QueryCount;

	DNSHeader* header = (DNSHeader*)q;
	memset(header, '\0', sizeof(DNSHeader));

	header->flags = htons(make_dns_flags(0, 0, 0, 0, 0, 0, 0, 0));
	header->QDCOUNT = htons(1);
	header->ID = htons((rand() % (USHRT_MAX + 1)));

	int QuestionStride = CreateQueryHostname(domainname, q + sizeof(DNSHeader));

	DNSQuestion* question = (DNSQuestion*)(q + QuestionStride + sizeof(DNSHeader));

	question->QTYPE = htons(flags);
	question->QCLASS = htons(1);

	int currLength = QuestionStride + sizeof(DNSHeader) + sizeof(DNSQuestion);

	return currLength;
}

DNSQueryResult* GetAddrByHostName(sockaddr_in *s, const char* str, int flags, int* answerCount)
{

	if (!s || !str) return NULL;

	if (s->sin_family != AF_INET)
	{
		ERRORLOG("Only IPv4 addresses to use for inital dns");
		return NULL;
	}

	srand(GetTickCount());

	sockaddr_in dnsResolver;

	dnsResolver.sin_addr = s->sin_addr;
	dnsResolver.sin_family = s->sin_family;
	dnsResolver.sin_port = htons(DEFAULT_DNS_PORT);

	int found = 0;

	int lErrorReturn = NODOMAIN;

	int recursed = 0;

	memset(RecursionLevelPointers, 0xFF, sizeof(RecursionLevelPointers));
	RecursionLevelPointer = -1;


	do
	{
		int currLength = CreateDNSQuestion(flags, str);

		PCSTR IPv4Decode = inet_ntop(dnsResolver.sin_family, &dnsResolver.sin_addr, HelperSpace, sizeof(HelperSpace));

		DEBUGLOG("Searching in IPv4 address %s", IPv4Decode);

		DNSHeader* header = (DNSHeader*)(QueryPool + QueryCount);

		SOCKET ConnectionSocket = INVALID_SOCKET;

		ConnectionSocket = socket(dnsResolver.sin_family, SOCK_DGRAM, IPPROTO_UDP);

		if (ConnectionSocket == INVALID_SOCKET) {
			DEBUGLOG("Error at socket(): %ld", WSAGetLastError());
			return NULL;
		}


		int res = connect(ConnectionSocket, ((sockaddr*)&dnsResolver), sizeof(dnsResolver));

		if (res == SOCKET_ERROR) {
			closesocket(ConnectionSocket);
			return NULL;
		}


		res = send(ConnectionSocket, (char*)header, currLength, 0);

		if (res == SOCKET_ERROR)
		{
			DEBUGLOG("send failed with error: %d", WSAGetLastError());
			closesocket(ConnectionSocket);
			return NULL;
		}

		DEBUGLOG("Bytes sent %ld", res);
			
		res = recv(ConnectionSocket, DNSAnswerPool + DNSAnswerCount, sizeof(DNSAnswerPool)-DNSAnswerCount, 0);
		if (res > 0) {
			DEBUGLOG("Bytes received: %d", res);
		}
		else if (res == 0)
			DEBUGLOG("Connection closed");
		else
			DEBUGLOG("recv failed with error: %d", WSAGetLastError());

		
		closesocket(ConnectionSocket);

		char* QueryHead = (char*)(DNSAnswerPool + DNSAnswerCount);

		DNSAnswerCount += res;

		QueryCount += currLength;

		DNSHeader* headera = (DNSHeader*)(QueryHead);

		DEBUGLOG("Header ID: %hx", ntohs(headera->ID));
		DEBUGLOG("flags ID: %hx", ntohs(headera->flags));
		print_dns_flags(ntohs(headera->flags));
		DEBUGLOG("QDCOUNT ID: %hx", ntohs(headera->QDCOUNT));
		DEBUGLOG("ANCOUNT ID: %hx", ntohs(headera->ANCOUNT));
		DEBUGLOG("NSCOUNT ID: %hx", ntohs(headera->NSCOUNT));
		DEBUGLOG("ARCOUNT ID: %hx", ntohs(headera->ARCOUNT));

		int ret = PrintHostName((char*)(QueryHead + sizeof(DNSHeader)), QueryHead, 0);

		uint16_t rcode = ntohs(headera->flags) & 0xf;

		uint16_t anCount = ntohs(headera->ANCOUNT);

		uint16_t nDomainCount = ntohs(headera->NSCOUNT);

		uint16_t adRecordCount = ntohs(headera->ARCOUNT);

		if (rcode == RCODE_NOERROR && anCount >= 1)
			found = 1;

		if (rcode == RCODE_SERVFAIL || rcode == RCODE_NOTIMPLEMENTED)
		{
			lErrorReturn = SERVERFAILURE;
			break;
		}

		if (rcode == RCODE_NXDOMAIN) {
			found = 1;
			if (!nDomainCount)
			{
				break;
			}
		}

		
	
		uint16_t offset = sizeof(DNSHeader);
		
		DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[RecordsBufferCounter];
		ref->packet = (void*)QueryHead;
		ref->offset = offset;
		ref->type = QUERYHOSTNAME;
		ref->size = sizeof(DNSRecordReference);
		ref->visited = 0;

		RecordsBufferCounter += sizeof(DNSRecordReference);

		int writeName = WriteHostName((QueryHead + offset), QueryHead, 0, &RecordsBuffer[RecordsBufferCounter]);

		ref->size += writeName;

		RecordsBufferCounter += writeName;

		offset += (writeName + sizeof(DNSQuestion));

		int recordsBufferStart = RecordsBufferCounter;

		for (uint16_t i = 0; i < anCount; i++)
		{
			char* ptr = QueryHead + offset;

			DNSPointer dnsPointer =
			{
				MAX_USHORT, MAX_USHORT, MAX_USHORT
			};

			int move = HandlePointerCondition((uint16_t*)ptr, &dnsPointer);

			ptr += move;
			offset += move;

			DNSAnswer* answer = (DNSAnswer*)ptr;

			offset += sizeof(DNSAnswer);

			dnsPointer.recordOffset = offset;

			offset += HandleDNSAnswer(answer, QueryHead, &dnsPointer);
			
		}

		for (uint16_t i = 0; i < nDomainCount; i++)
		{
			char* ptr = QueryHead + offset;

			DNSPointer dnsPointer =
			{
				MAX_USHORT, MAX_USHORT, MAX_USHORT
			};

			int move = HandlePointerCondition((uint16_t*)ptr, &dnsPointer);

			ptr += move;
			offset += move;

			DNSAnswer* answer = (DNSAnswer*)ptr;

			offset += sizeof(DNSAnswer);

			dnsPointer.recordOffset = offset;
		
			offset += HandleDNSNSNames(answer, QueryHead, &dnsPointer);
		}

		for (uint16_t i = 0; i < adRecordCount; i++)
		{
			char* ptr = QueryHead + offset;

			DNSPointer dnsPointer =
			{
				MAX_USHORT, MAX_USHORT, MAX_USHORT
			};

			int move = HandlePointerCondition((uint16_t*)ptr, &dnsPointer);

			ptr += move;
			offset += move;

			DNSAnswer* answer = (DNSAnswer*)ptr;

			offset += sizeof(DNSAnswer);

			dnsPointer.recordOffset = offset;

			offset += HandleDNSAdditional(answer, QueryHead, &dnsPointer);
		}

		
		lErrorReturn = anCount;

		if (!found || RecursionLevelPointer >= 0)
		{
			found = RecurseDNSResolver(&dnsResolver, recordsBufferStart);
		}
	} while (!found);

	DNSQueryResult* returnHeader = (DNSQueryResult*)&FunctionAnswerPool[FunctionAnswerPtr];

	if (lErrorReturn > 0) {

		int ResultCount = ProcessBuffer(returnHeader);

		*answerCount = ResultCount;
	}
	else {
		*answerCount = lErrorReturn;
	}

	DNSAnswerCount = 0;
	QueryCount = 0;
	RecordsBufferCounter = 0;
	RecordsBufferReader = 0;

	return returnHeader;
}

static int DeDeuplicateIPv4(char* recordBuffer, uint16_t count, uint16_t* recordoffsets, int addr)
{
	int dup = 0;
	for (uint16_t i = 0; i < count; i++)
	{
		DNSRecordReference* aRef1 = (DNSRecordReference*)&recordBuffer[recordoffsets[i]];
		if (aRef1->type == A)
		{
			DNSARecord* aRef = (DNSARecord*)&recordBuffer[recordoffsets[i] + sizeof(DNSRecordReference)];

			int lAddr = aRef->addr;

			if (addr == lAddr)
			{
				dup = 1;
				break;
			}
		}
	}

	return dup;
}

static int DeDeuplicateIPv6(char* recordBuffer, uint16_t count, uint16_t *recordoffsets, char* addr)
{
	int dup = 0;

	for (uint16_t i = 0; i < count; i++)
	{
		DNSRecordReference* aRef1 = (DNSRecordReference*)&recordBuffer[recordoffsets[i]];
		if (aRef1->type == AAAA)
		{
			
			DNSAAAARecord* aRef = (DNSAAAARecord*)&recordBuffer[recordoffsets[i] + sizeof(DNSRecordReference)];

			if (!memcmp(aRef->addr, addr, 16))
			{
				dup = 1;
				break;
			}
		}
	}

	return dup;
}

static int ProcessBuffer(DNSQueryResult* resultSpace)
{
	int ResultCount = 0;
	DNSQueryResult* resultPtr = resultSpace;
	for (int j = RecordsBufferReader; j < RecordsBufferCounter;) {
		DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[j];
		if (!ref->visited) {
			memset(resultPtr, 0, sizeof(DNSQueryResult));
			ref->visited = 1;
			switch (ref->type)
			{
			case A:
			{
				DNSARecord* record = (DNSARecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->referenceHostNameRecordID];

				if (aRef1->type == QUERYHOSTNAME)
				{
					char* ptr = (char*)&RecordsBuffer[record->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					PrintRecordHostname(ptr);

					int hostNameCount = 0;
		
					COPYSTRING(ptr, resultPtr->hostname, hostNameCount);
				}

				int addr = record->addr;

				resultPtr->ipv4or6 = A;
				resultPtr->ipv4 = addr;

				PrintIPv4(addr);

				resultPtr++;

				ResultCount++;

				break;
			}
			case CNAME:
			{
				DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
				char* ptr = (char*)&RecordsBuffer[j + sizeof(DNSRecordReference) + sizeof(DNSCNAMERecord)];
				DEBUGLOG("Hostname : ");
				PrintRecordHostname(ptr);

				memset(resultPtr->hostname, 0, sizeof(resultPtr->hostname));
				int hostNameCount = 0;
				COPYSTRING(ptr, resultPtr->hostname, hostNameCount);

				int aliasNameCount = 0;

				if (record->queryAlias != ~0ui16)
				{
					DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->queryAlias];

					char* ptr = NULL;

					int off = 0;

					if (aRef1->type == QUERYHOSTNAME)
					{
						off = sizeof(DNSRecordReference);

					}
					else if (aRef1->type == CNAME)
					{
						off =  sizeof(DNSRecordReference) + sizeof(DNSCNAMERecord);
					}

					ptr = (char*)&RecordsBuffer[record->queryAlias + off];
					DEBUGLOG("Alias Hostname : ");
					PrintRecordHostname(ptr);

					COPYSTRING(ptr, resultPtr->aliasname, aliasNameCount);
				}

				if (record->arecordcount)
				{
					for (uint16_t g = 0; g < record->arecordcount; g++)
					{
						DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];
						aRef1->visited = 1;

						DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						int addr = aRef->addr;

						if (DeDeuplicateIPv4(RecordsBuffer, g, record->arecordid, addr))
						{
							continue;
						}

						PrintIPv4(addr);

						resultPtr->ipv4or6 = A;
						resultPtr->ipv4 = addr;


						DNSQueryResult* prev = resultPtr;
						resultPtr++;
						ResultCount++;
						memset(resultPtr, 0, sizeof(DNSQueryResult));

						memcpy(resultPtr->aliasname, prev->aliasname, aliasNameCount);
						memcpy(resultPtr->hostname, prev->hostname, hostNameCount);
					}
				}


				break;
			}
			case NS:

			{
				DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
				char* ptr = (char*)&RecordsBuffer[j + sizeof(DNSRecordReference) + sizeof(DNSNSRecord)];
				DEBUGLOG("Hostname : ");
				PrintRecordHostname(ptr);

				memset(resultPtr->hostname, 0, sizeof(resultPtr->hostname));
				int hostNameCount = 0;
				COPYSTRING(ptr, resultPtr->hostname, hostNameCount);

				int aliasNameCount = 0;

				if (record->queryAlias != ~0ui16)
				{
					DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->queryAlias];

					char* ptr = NULL;

					int off = 0;

					if (aRef1->type == QUERYHOSTNAME)
					{
						off = sizeof(DNSRecordReference);

					}

					ptr = (char*)&RecordsBuffer[record->queryAlias + off];
					DEBUGLOG("Alias Hostname : ");
					PrintRecordHostname(ptr);

					COPYSTRING(ptr, resultPtr->aliasname, aliasNameCount);
				}

				if (record->arecordcount)
				{
					for (uint16_t g = 0; g < record->arecordcount; g++)
					{
						DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];
						aRef1->visited = 1;

						if (aRef1->type == A)
						{
							DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

							int addr = aRef->addr;

							if (DeDeuplicateIPv4(RecordsBuffer, g, record->arecordid, addr))
							{
								continue;
							}

							resultPtr->ipv4or6 = A;
							resultPtr->ipv4 = addr;
							PrintIPv4(addr);
						}
						else if (aRef1->type == AAAA) 
						{
							DNSAAAARecord* aRef = (DNSAAAARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];


							if (DeDeuplicateIPv6(RecordsBuffer, g, record->arecordid, aRef->addr))
							{
								continue;
							}

							PrintIPv6(aRef->addr);
							resultPtr->ipv4or6 = AAAA;
							memcpy(resultPtr->ipv6, aRef->addr, 16);
						}

						

						DNSQueryResult* prev = resultPtr;
						resultPtr++;
						ResultCount++;
						memset(resultPtr, 0, sizeof(DNSQueryResult));

						memcpy(resultPtr->aliasname, prev->aliasname, aliasNameCount);
						memcpy(resultPtr->hostname, prev->hostname, hostNameCount);
						
					}
				}

				

			}

			case MX:
			{

				DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
				char* ptr = (char*)&RecordsBuffer[j + sizeof(DNSRecordReference) + sizeof(DNSMXRecord)];
				
				DEBUGLOG("Hostname : ");
				PrintRecordHostname(ptr);

				memset(resultPtr->hostname, 0, sizeof(resultPtr->hostname));
				
				int hostNameCount = 0;

				COPYSTRING(ptr, resultPtr->hostname, hostNameCount);

				int aliasNameCount = 0;

				if (record->queryAlias != ~0ui16)
				{
					DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->queryAlias];


					int off = 0;

					if (aRef1->type == QUERYHOSTNAME)
					{
						off = sizeof(DNSRecordReference);

					}

					char* ptr = (char*)&RecordsBuffer[record->queryAlias + off];
					DEBUGLOG("Alias Hostname : ");
					PrintRecordHostname(ptr);

					COPYSTRING(ptr, resultPtr->aliasname, aliasNameCount);
				}

				if (record->arecordcount)
				{
					for (uint16_t g = 0; g < record->arecordcount; g++)
					{
						DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];
						aRef1->visited = 1;

						

						if (aRef1->type == A)
						{

							


							DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

							int addr = aRef->addr;

							if (DeDeuplicateIPv4(RecordsBuffer, g, record->arecordid, addr))
							{
								continue;
							}

							
							resultPtr->ipv4or6 = A;
							resultPtr->ipv4 = addr;
							PrintIPv4(addr);
						}
						else if (aRef1->type == AAAA)
						{
							DNSAAAARecord* aRef = (DNSAAAARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];



							if (DeDeuplicateIPv6(RecordsBuffer, g, record->arecordid, aRef->addr))
							{
								continue;
							}

							PrintIPv6(aRef->addr);
							resultPtr->ipv4or6 = AAAA;
							memcpy(resultPtr->ipv6, aRef->addr, 16);
						}



						DNSQueryResult* prev = resultPtr;
						resultPtr++;
						ResultCount++;
						memset(resultPtr, 0, sizeof(DNSQueryResult));

						memcpy(resultPtr->aliasname, prev->aliasname, aliasNameCount);
						memcpy(resultPtr->hostname, prev->hostname, hostNameCount);

					}
				}

				break;
			}

			}
		}
		j += ref->size;

	}
	return ResultCount;
}

void ShowDNSQueryResult(DNSQueryResult* result)
{
	printf("%s\n", result->hostname);
	printf("%s\n", result->aliasname);
	if (result->ipv4or6 == A)
	{
		int addr = result->ipv4;
		printf("IPv4 Address is : \n");
		for (int i = 0; i < 3; i++)
		{
			printf("%d.", ((addr & 0xff000000) >> 24));
			addr <<= 8;
		}
		printf("%d\n", ((addr & 0xff000000) >> 24));
	}
	else if (result->ipv4or6 == AAAA) {

		printf("IPv6 Address is : \n");
		char* addr = result->ipv6;
		for (int i = 15; i > 0; i -= 4)
		{
			for (int j = 0; j < 4 && (i - j) >= 1; j++)
			{
				printf("%x", (unsigned char)addr[i-j]);
			}
			if (i > 4) printf(".");
		}
		printf("%x\n", addr[0]);
	}
}

static void PrintRecordHostname(char* ptr)
{
#if DNS_LOG_LVL > 2
	while(*ptr)
	{
		printf("%c", *ptr++);
	}
	printf("");
#endif
}

static void PrintIPv4(uint32_t addr)
{
#if DNS_LOG_LVL > 2
	DEBUGLOG("Address is : ");
	for (int i = 0; i < 3; i++)
	{
		printf("%d.", ((addr & 0xff000000) >> 24));
		addr <<= 8;
	}
	printf("%d\n", ((addr & 0xff000000) >> 24));
#endif
}

static void PrintIPv6(char* addr)
{
#if DNS_LOG_LVL > 2
	DEBUGLOG("Address is : ");
	for (int i = 15; i > 0; i-=4)
	{
		for (int j = 0; j < 4 && (i - j) >= 1; j++)
		{
			printf("%x", addr[j]);
		}
		if (i > 4) printf(".");
	}
	printf("%x\n", addr[0]);
#endif
}

static int HandlePointerCondition(uint16_t* iter, DNSPointer* pointer)
{
	uint16_t lPointer = ntohs(*iter);;
	
	int ret = 0;

	if (lPointer & 0xC000)
	{
		lPointer &= 0x3fff;
		int i = 0;
		for (int j = RecordsBufferReader; j < RecordsBufferCounter;) {
			DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[j];
			if (ref->offset == lPointer)
			{
				DEBUGLOG("This is a reference to the %d response", i+1);
				pointer->internalRecordBufferOffset = (uint16_t)j;
				break;
			}
			j += ref->size;
			i++;
		}

		pointer->dnsReferenceRecordOffset = lPointer;

		ret = 2;
	}

	return ret;
}

static int HandleDNSNSNames(DNSAnswer* answer, char* queryHead, DNSPointer* pointer)
{
	


	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;
	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[RecordsBufferCounter];
	ref->packet = (void*)queryHead;
	ref->offset = pointer->recordOffset;
	ref->type = ntohs(answer->TYPE);
	ref->visited = 0;

	int len = ntohs(answer->RDLENGTH);

	char* RDDATA = (char*)(answer + 1);

	RecordsBufferCounter += sizeof(DNSRecordReference);

	uint16_t referenceLocation = pointer->internalRecordBufferOffset;

	switch (ref->type)
	{
		case SOA:
		{
			if (pointer->dnsReferenceRecordOffset != MAX_USHORT)
			{
				char* topLevelDomain = queryHead + pointer->dnsReferenceRecordOffset;
				DEBUGLOG("TOP LEVEL DOMAIN BEING SPECFIED: ");
				PrintHostName(topLevelDomain, queryHead, 0);
			}

			int move = PrintHostName(RDDATA, queryHead, 0);

			RDDATA += move;

			move = PrintHostName(RDDATA, queryHead, 0);

			RDDATA += move;

			DEBUGLOG("Serial is : %hu  ", ntohs(*((uint16_t*)RDDATA)));
			RDDATA += 2;
			DEBUGLOG("Refresh is : %hu  ", ntohs(*((uint16_t*)RDDATA)));
			RDDATA += 2;
			DEBUGLOG("Retry is : %hu  ", ntohs(*((uint16_t*)RDDATA)));
			RDDATA += 2;
			DEBUGLOG("Expire is : %hu  ", ntohs(*((uint16_t*)RDDATA)));
			RDDATA += 2;
			DEBUGLOG("Minimum is : %hu  ", ntohs(*((uint16_t*)RDDATA)));
			RDDATA += 2;
			break;
		}

		case NS:
		{
			PrintHostName(RDDATA, queryHead, 0);
			DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[RecordsBufferCounter];
			RecordsBufferCounter += sizeof(DNSNSRecord);
			record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
			record->arecordcount = 0;
			record->queryAlias = referenceLocation;
			RecordsBufferCounter += record->namelength;
			break;
		}
	}

	ref->size = RecordsBufferCounter - startReference;

	return len;
}

static int HandleDNSAnswer(DNSAnswer* answer, char* queryHead, DNSPointer* pointer)
{
	


	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;


	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[RecordsBufferCounter];
	ref->packet = (void*)queryHead;
	ref->offset = pointer->recordOffset;
	ref->type = ntohs(answer->TYPE);
	ref->visited = 0;

	int len = ntohs(answer->RDLENGTH);

	uint16_t referenceLocation = pointer->internalRecordBufferOffset;

	RecordsBufferCounter += sizeof(DNSRecordReference);

	char* RDDATA = (char*)(answer + 1);

	switch (ref->type)
	{
	case A:
	{
		uint32_t addr = 0;
		for (int i = 0; i < len - 1; i++)
		{
			addr |= (RDDATA[i] & 0xff);
			addr <<= 8;
		}
		addr |= (RDDATA[3] & 0xff);

		

		DNSARecord* record = (DNSARecord*)&RecordsBuffer[RecordsBufferCounter];
		record->addr = addr;
		PrintIPv4(addr);


		record->referenceHostNameRecordID = referenceLocation;
		
		if (referenceLocation != MAX_USHORT)
		{

			DNSRecordReference* nameRef = (DNSRecordReference*)&RecordsBuffer[referenceLocation];

			if (nameRef->type == CNAME)
			{
				DNSCNAMERecord* record1 = (DNSCNAMERecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record1->arecordid[record1->arecordcount++] = startReference;
			}
			else if (nameRef->type == NS) {
				DNSNSRecord* record1 = (DNSNSRecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record1->arecordid[record1->arecordcount++] = startReference;
			}
		}
		RecordsBufferCounter += sizeof(DNSARecord);
	}
	break;
	case CNAME:
	{
		PrintHostName(RDDATA, queryHead, 0);
		DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[RecordsBufferCounter];
		RecordsBufferCounter += sizeof(DNSCNAMERecord);
		record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
		record->arecordcount = 0;	
		record->queryAlias = referenceLocation;
		RecordsBufferCounter += record->namelength;
		break;
	}
	case NS:
	{
		PrintHostName(RDDATA, queryHead, 0);
		DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[RecordsBufferCounter];
		RecordsBufferCounter += sizeof(DNSNSRecord);
		record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
		record->arecordcount = 0;
		record->queryAlias = referenceLocation;
		RecordsBufferCounter += record->namelength;
		break;
	}
	case MX:
	{
		uint16_t* pref = (uint16_t*)RDDATA;
		RDDATA += 2;
		ref->offset += 2;
		PrintHostName(RDDATA, queryHead, 0);
		DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[RecordsBufferCounter];
		RecordsBufferCounter += sizeof(DNSMXRecord);
		record->preference = ntohs(*pref);
		record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
		record->arecordcount = 0;
		record->queryAlias = referenceLocation;
		RecordsBufferCounter += record->namelength;
		break;
	}
	default:
		ERRORLOG("Unhandled response");
		break;

	}

	ref->size = RecordsBufferCounter - startReference;

	return len;
}

static int HandleDNSAdditional(DNSAnswer* answer, char* queryHead, DNSPointer* pointer)
{

	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[RecordsBufferCounter];
	ref->packet = (void*)queryHead;
	ref->offset = pointer->recordOffset;
	ref->type = ntohs(answer->TYPE);
	ref->visited = 0;

	int len = ntohs(answer->RDLENGTH);

	RecordsBufferCounter += sizeof(DNSRecordReference);

	uint16_t referenceLocation = pointer->internalRecordBufferOffset;

	char* RDDATA = (char*)(answer + 1);

	switch (ref->type)
	{
	case A:
	{

		uint32_t addr = 0;
		for (int i = 0; i < len - 1; i++)
		{
			addr |= (RDDATA[i] & 0xff);
			addr <<= 8;
		}
		addr |= (RDDATA[len-1] & 0xff);

		PrintIPv4(addr);

		DNSARecord* record = (DNSARecord*)&RecordsBuffer[RecordsBufferCounter];
		record->addr = addr;
		record->referenceHostNameRecordID = referenceLocation;

		if (referenceLocation != MAX_USHORT)
		{
			DNSRecordReference* nameRef = (DNSRecordReference*)&RecordsBuffer[referenceLocation];

			if (nameRef->type == CNAME)
			{
				DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record->arecordid[record->arecordcount++] = startReference;
			}
			else if (nameRef->type == NS) {
				DNSNSRecord* record1 = (DNSNSRecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record1->arecordid[record1->arecordcount++] = startReference;
			}
			else if (nameRef->type == MX)
			{
				DNSMXRecord* record1 = (DNSMXRecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record1->arecordid[record1->arecordcount++] = startReference;
			}
		}

		RecordsBufferCounter += sizeof(DNSARecord);
	}
	break;
	case AAAA:
	{
		DNSAAAARecord* record = (DNSAAAARecord*)&RecordsBuffer[RecordsBufferCounter];
		record->referenceHostNameRecordID = referenceLocation;
		for (int i = 0; i < len; i++)
		{
			record->addr[15-i] = (RDDATA[i] & 0xff);
		}

		

		if (referenceLocation != MAX_USHORT)
		{
			DNSRecordReference* nameRef = (DNSRecordReference*)&RecordsBuffer[referenceLocation];

			if (nameRef->type == CNAME)
			{
				DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record->arecordid[record->arecordcount++] = startReference;
			}
			else if (nameRef->type == NS) {
				DNSNSRecord* record1 = (DNSNSRecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record1->arecordid[record1->arecordcount++] = startReference;
			}

			else if (nameRef->type == MX)
			{
				DNSMXRecord* record1 = (DNSMXRecord*)&RecordsBuffer[referenceLocation + sizeof(DNSRecordReference)];
				record1->arecordid[record1->arecordcount++] = startReference;
			}
		}

		RecordsBufferCounter += sizeof(DNSAAAARecord);
		break;

	}

	default:
		ERRORLOG("Unhandled response");
		break;

	}

	ref->size = RecordsBufferCounter - startReference;

	return len;
}