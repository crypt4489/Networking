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

#define DNS_LOG_LVL 1

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


#define COPYSTRING(src, dest, count) \
	do { \
		dest[count] = *src; \
		count++; \
		src++; \
	} while(*src) \

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



#define DNSPOOLSIZE 512*4
#define QUERYPOOLSIZE 256*4
#define FUNCANSWEPOOL 200000


static CACHE_ALIGN char QueryPool[QUERYPOOLSIZE];
static int QueryCount = 0;
static CACHE_ALIGN char DNSAnswerPool[DNSPOOLSIZE];
static int DNSAnswerCount = 0;

static CACHE_ALIGN char RecordsBuffer[1032];
static int RecordsBufferCounter = 0;
static int RecordsBufferReader = 0;

static CACHE_ALIGN char HelperSpace[128];

static CACHE_ALIGN char FunctionAnswerPool[FUNCANSWEPOOL];
static int FunctionAnswerPtr = 0;

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
		if (!count) {
			if (terminate) {
				*write++ = '.';
				i++;
			}
			else {
				*write++ = '\0';
				i++;
			}	
		}

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
		printf("");
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

	return i;
}

static int HandleDNSAnswer(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t refsAndOffset[3], uint16_t ptrCount);

static int HandleDNSNSNames(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t refsAndOffset[3], uint16_t ptrCount, int *found);

static int HandlePointerCondition(uint16_t* iter, uint16_t* ptr, uint16_t* referenceCounter);

static int HandleDNSAdditional(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t refsAndOffset[3], uint16_t ptrCount);

static int ProcessBuffer(DNSQueryResult* resultSpace);

static int ReadPointerForResponse(char* ptr, uint16_t* ptrs, uint16_t* pointerCount);

static void PrintIPv4(uint32_t addr);

static void PrintIPv6(char* addr);

static void PrintRecordHostname(char* ptr);

static int DeDeuplicateIPv4(char* recordBuffer, uint16_t count, uint16_t* recordoffsets, int addr);

static int DeDeuplicateIPv6(char* recordBuffer, uint16_t count, uint16_t* recordoffsets, char* addr);

DNSQueryResult* GetAddrByHostName(sockaddr_in *s, const char* str, int flags, int* answerCount)
{

	if (!s || !str) return NULL;

	if (s->sin_family != AF_INET)
	{
		DEBUGLOG("Only IPv4 addresses to use for inital dns");
		return NULL;
	}

	srand(GetTickCount());

	sockaddr_in dnsResolver;

	dnsResolver.sin_addr = s->sin_addr;
	dnsResolver.sin_family = s->sin_family;
	dnsResolver.sin_port = htons(DEFAULT_DNS_PORT);

	int found = 0;

	char* q = QueryPool + QueryCount;

	DNSHeader* header = (DNSHeader*)q;
	memset(header, '\0', sizeof(DNSHeader));

	header->flags = htons(make_dns_flags(0, 0, 0, 0, 1, 0, 0, 0));
	header->QDCOUNT = htons(1);

	int QuestionStride = CreateQueryHostname(str, q + sizeof(DNSHeader));

	DNSQuestion* question = (DNSQuestion*)(q + QuestionStride + sizeof(DNSHeader));

	question->QTYPE = htons(flags);
	question->QCLASS = htons(1);

	int currLength = QuestionStride + sizeof(DNSHeader) + sizeof(DNSQuestion);

	int lAnswerCount = 0;
	
	do
	{
		PCSTR IPv4Decode = inet_ntop(dnsResolver.sin_family, &dnsResolver.sin_addr, HelperSpace, sizeof(HelperSpace));

		DEBUGLOG("Searching in IPv4 address %s", IPv4Decode);

		unsigned short ID = (rand() % (USHRT_MAX + 1));

		header->ID = htons(ID);
	
		int prevAnswer = DNSAnswerCount;

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


		res = send(ConnectionSocket, q, currLength, 0);

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

		if (anCount >= 1 && rcode == RCODE_NOERROR)
			found = 1;
		else if (anCount == 0)
			found = 1;

		if (rcode == RCODE_SERVFAIL)
			break;

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

		int writeName = WriteHostName((char*)(QueryHead + sizeof(DNSHeader)), QueryHead, 0, (char*)&RecordsBuffer[RecordsBufferCounter]);

		ref->size += writeName;

		RecordsBufferCounter += writeName;

		offset += QuestionStride + sizeof(DNSQuestion);

		for (uint16_t i = 0; i < anCount; i++)
		{
			char* ptr = QueryHead + offset;

			uint16_t ptrCount = 1;

			uint16_t ptrs[3] = { offset, MAX_USHORT, MAX_USHORT };

			int move = ReadPointerForResponse(ptr, ptrs, &ptrCount);

			ptr += move;
			offset += move;

			DNSAnswer* answer = (DNSAnswer*)ptr;

			ptr += sizeof(DNSAnswer);
			offset += sizeof(DNSAnswer);

			
			ptrs[0] = offset;

			offset += HandleDNSAnswer(answer, ptr, QueryHead, ptrs, ptrCount);
			
		}

		for (uint16_t i = 0; i < nDomainCount; i++)
		{
			char* ptr = QueryHead + offset;

			uint16_t ptrCount = 1;

			uint16_t ptrs[3] = { offset, MAX_USHORT, MAX_USHORT };

			int move = ReadPointerForResponse(ptr, ptrs, &ptrCount);

			ptr += move;
			offset += move;

			DNSAnswer* answer = (DNSAnswer*)ptr;

			ptr += sizeof(DNSAnswer);
			offset += sizeof(DNSAnswer);

			ptrs[0] = offset;
		
			offset += HandleDNSNSNames(answer, ptr, QueryHead, ptrs, ptrCount, &found);
		}

		for (uint16_t i = 0; i < adRecordCount; i++)
		{
			char* ptr = QueryHead + offset;

			uint16_t ptrCount = 1;

			uint16_t ptrs[3] = { offset, MAX_USHORT, MAX_USHORT };

			int move = ReadPointerForResponse(ptr, ptrs, &ptrCount);

			ptr += move;
			offset += move;

			DNSAnswer* answer = (DNSAnswer*)ptr;

			ptr += sizeof(DNSAnswer);
			offset += sizeof(DNSAnswer);

			ptrs[0] = offset;

			offset += HandleDNSAdditional(answer, ptr, QueryHead, ptrs, ptrCount);
		}

		lAnswerCount = anCount;
		
	} while (!found);

	DNSQueryResult* returnHeader = (DNSQueryResult*)&FunctionAnswerPool[FunctionAnswerPtr];

	int ResultCount = ProcessBuffer(returnHeader);

	*answerCount = ResultCount;

	DNSAnswerCount = 0;
	QueryCount = 0;
	RecordsBufferCounter = 0;
	RecordsBufferReader = 0;

	return returnHeader;
}

static int ReadPointerForResponse(char* ptr, uint16_t* ptrs, uint16_t* pointerCount) {
	int i = 0;

	uint16_t referencePtr = ~0ui16, rawPtr = ~0ui16, ptrCount = 1;

	int move = HandlePointerCondition((uint16_t*)ptr, &rawPtr, &referencePtr);

	if (referencePtr != ~0ui16)
	{
		ptrs[2] = referencePtr;
		ptrCount++;
	}

	if (rawPtr != ~0ui16)
	{
		ptrs[1] = rawPtr;
		ptrCount++;
	}

	*pointerCount = ptrCount;

	return move;
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
				while (*ptr)
				{
					resultPtr->hostname[hostNameCount] = *ptr;
					ptr++;
					hostNameCount++;
				}

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

static int HandlePointerCondition(uint16_t* iter, uint16_t *ptr, uint16_t* referenceCounter)
{
	uint16_t pointer = 0;

	pointer = ntohs(*iter);
	int ret = 0;

	if (pointer & 0xC000)
	{
		pointer &= 0x3fff;
		int i = 0;
		for (int j = RecordsBufferReader; j < RecordsBufferCounter;) {
			DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[j];
			if (ref->offset == pointer)
			{
				DEBUGLOG("This is a reference to the %d response", i+1);
				*referenceCounter = (uint16_t)j;
				break;
			}
			j += ref->size;
			i++;
		}

		*ptr = pointer;

		ret = 2;
	}

	return ret;
}

static int HandleDNSNSNames(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t domainPtr[3], uint16_t ptrCount, int* found)
{
	char* ptr = RDDATA;


	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;
	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[RecordsBufferCounter];
	ref->packet = (void*)queryHead;
	ref->offset = *domainPtr;
	ref->type = ntohs(answer->TYPE);
	ref->visited = 0;

	int len = ntohs(answer->RDLENGTH);

	

	RecordsBufferCounter += sizeof(DNSRecordReference);

	switch (ref->type)
	{
		case SOA:
		{
			*found = 1;
			if (ptrCount > 1)
			{
				char* topLevelDomain = queryHead + domainPtr[1];
				char len = topLevelDomain[0];
				DEBUGLOG("TOP LEVEL DOMAIN BEING SPECFIED: ");
				PrintHostName(topLevelDomain, queryHead, 0);
			}

			int move = PrintHostName(ptr, queryHead, 0);

			ptr += move;

			move = PrintHostName(ptr, queryHead, 0);

			ptr += move;

			DEBUGLOG("Serial is : %hu  ", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			DEBUGLOG("Refresh is : %hu  ", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			DEBUGLOG("Retry is : %hu  ", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			DEBUGLOG("Expire is : %hu  ", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			DEBUGLOG("Minimum is : %hu  ", ntohs(*((uint16_t*)ptr)));
			ptr += 2;


			break;
		}
	}

	ref->size = RecordsBufferCounter - startReference;

	return len;
}

static int HandleDNSAnswer(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t refsAndOffset[3], uint16_t ptrCount)
{
	char* ptr = RDDATA;


	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;


	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[RecordsBufferCounter];
	ref->packet = (void*)queryHead;
	ref->offset = *refsAndOffset;
	ref->type = ntohs(answer->TYPE);
	ref->visited = 0;

	int len = ntohs(answer->RDLENGTH);

	

	RecordsBufferCounter += sizeof(DNSRecordReference);

	switch (ref->type)
	{
	case A:
	{
		uint32_t addr = 0;
		for (int i = 0; i < len - 1; i++)
		{
			addr |= (ptr[i] & 0xff);
			addr <<= 8;
		}
		addr |= (ptr[3] & 0xff);

		DNSARecord* record = (DNSARecord*)&RecordsBuffer[RecordsBufferCounter];
		record->addr = addr;
		record->referenceHostNameRecordID = refsAndOffset[2];
		
		PrintIPv4(addr);

		DNSRecordReference *nameRef = (DNSRecordReference*)&RecordsBuffer[refsAndOffset[2]];

		if (nameRef->type == CNAME)
		{
			DNSCNAMERecord* record1 = (DNSCNAMERecord*)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}
		else if (nameRef->type == NS) {
			DNSNSRecord* record1 = (DNSNSRecord*)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}

		RecordsBufferCounter += sizeof(DNSARecord);
	}
	break;
	case CNAME:
	{
		PrintHostName(ptr, queryHead, 0);
		DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[RecordsBufferCounter];
		RecordsBufferCounter += sizeof(DNSCNAMERecord);
		record->namelength = WriteHostName(ptr, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
		record->arecordcount = 0;	
		record->queryAlias = refsAndOffset[2];	
		RecordsBufferCounter += record->namelength;
		break;
	}
	case NS:
	{
		PrintHostName(ptr, queryHead, 0);
		DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[RecordsBufferCounter];
		RecordsBufferCounter += sizeof(DNSNSRecord);
		record->namelength = WriteHostName(ptr, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
		record->arecordcount = 0;
		record->queryAlias = refsAndOffset[2];
		RecordsBufferCounter += record->namelength;
		break;
	}
	case MX:
	{
		uint16_t* pref = (uint16_t*)ptr;
		ptr += 2;
		ref->offset += 2;
		PrintHostName(ptr, queryHead, 0);
		DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[RecordsBufferCounter];
		RecordsBufferCounter += sizeof(DNSMXRecord);
		record->preference = ntohs(*pref);
		record->namelength = WriteHostName(ptr, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
		record->arecordcount = 0;
		record->queryAlias = refsAndOffset[2];
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

static int HandleDNSAdditional(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t refsAndOffset[3], uint16_t ptrCount)
{
	char* ptr = RDDATA;


	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[RecordsBufferCounter];
	ref->packet = (void*)queryHead;
	ref->offset = *refsAndOffset;
	ref->type = ntohs(answer->TYPE);
	ref->visited = 0;

	int len = ntohs(answer->RDLENGTH);

	RecordsBufferCounter += sizeof(DNSRecordReference);

	switch (ref->type)
	{
	case A:
	{

		uint32_t addr = 0;
		for (int i = 0; i < len - 1; i++)
		{
			addr |= (ptr[i] & 0xff);
			addr <<= 8;
		}
		addr |= (ptr[len-1] & 0xff);

		PrintIPv4(addr);

		DNSARecord* record = (DNSARecord*)&RecordsBuffer[RecordsBufferCounter];
		record->addr = addr;
		record->referenceHostNameRecordID = refsAndOffset[ptrCount-1];


		DNSRecordReference* nameRef = (DNSRecordReference*)&RecordsBuffer[refsAndOffset[ptrCount-1]];

		if (nameRef->type == CNAME)
		{
			DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[refsAndOffset[ptrCount-1] + sizeof(DNSRecordReference)];
			record->arecordid[record->arecordcount++] = startReference;
		}
		else if (nameRef->type == NS) {
			DNSNSRecord* record1 = (DNSNSRecord*)&RecordsBuffer[refsAndOffset[ptrCount-1] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}
		else if (nameRef->type == MX)
		{
			DNSMXRecord* record1 = (DNSMXRecord*)&RecordsBuffer[refsAndOffset[ptrCount-1] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}

		RecordsBufferCounter += sizeof(DNSARecord);
	}
	break;
	case AAAA:
	{
		DNSAAAARecord* record = (DNSAAAARecord*)&RecordsBuffer[RecordsBufferCounter];
		record->referenceHostNameRecordID = refsAndOffset[ptrCount-1];
		for (int i = 0; i < len; i++)
		{
			record->addr[15-i] = (ptr[i] & 0xff);
		}

		DNSRecordReference* nameRef = (DNSRecordReference*)&RecordsBuffer[refsAndOffset[ptrCount-1]];

		if (nameRef->type == CNAME)
		{
			DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[refsAndOffset[ptrCount-1] + sizeof(DNSRecordReference)];
			record->arecordid[record->arecordcount++] = startReference;
		}
		else if (nameRef->type == NS) {
			DNSNSRecord* record1 = (DNSNSRecord*)&RecordsBuffer[refsAndOffset[ptrCount-1] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}

		else if (nameRef->type == MX)
		{
			DNSMXRecord* record1 = (DNSMXRecord*)&RecordsBuffer[refsAndOffset[ptrCount-1] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
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