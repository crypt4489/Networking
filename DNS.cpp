#include "DNS.h"

#include <stdio.h>
#include <ws2tcpip.h>
#include <sysinfoapi.h>
#include <stdlib.h>
#include <limits.h>

#define DEFAULT_DNS_PORT 53
#define CACHE_LINE  32
#define CACHE_ALIGN __declspec(align(CACHE_LINE))

#define MAX_USHORT (uint16_t)~0ui16

#define QUERYHOSTNAME MAX_USHORT

typedef struct dns_record_reference
{
	uint16_t type;
	uint16_t offset;
	void* packet;
	uint32_t size;
	uint32_t visited;
} DNSRecordReference, *PDNSRecordReference;

typedef struct dns_answer_a
{
	uint16_t referenceHostNameRecordID;
	uint32_t addr;
} DNSARecord, *PDNSARecord;

typedef struct dns_answer_aaaa
{
	uint16_t referenceHostNameRecordID;
	char addr[16];
}DNSAAAARecord, *PDNSAAAARecord;

typedef struct dns_answer_cname {
	uint16_t namelength;
	uint16_t arecordcount;
	uint16_t arecordid[10];
	uint32_t queryAlias;
} DNSCNAMERecord, *PDNSCNAMERecord;

typedef struct dns_answer_ns {
	uint16_t namelength;
	uint16_t arecordcount;
	uint16_t arecordid[10];
	uint32_t queryAlias;
} DNSNSRecord, *PDNSNSRecord;

static CACHE_ALIGN char QueryPool[256*4];
static int QueryCount = 0;
static CACHE_ALIGN char AnswerPool[512*4];
static int AnswerCount = 0;

static char helperstring[80];
static CACHE_ALIGN char RecordsBuffer[1032];
static int RecordsBufferCounter = 0;
static int RecordsBufferReader = 0;



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
	printf("QR=%d \n", (flags >> 15) & 0x1);
	printf("OpCode=%d \n", (flags >> 11) & 0xF);
	printf("AA=%d \n", (flags >> 10) & 0x1);
	printf("TC=%d \n", (flags >> 9) & 0x1);
	printf("RD=%d \n", (flags >> 8) & 0x1);
	printf("RA=%d \n", (flags >> 7) & 0x1);
	printf("Z=%d \n", (flags >> 4) & 0x7);
	printf("RCODE=%d\n", (flags >> 0) & 0xF);
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
	int i = 0;
	while (count-- > 0)
	{
		printf("%c", *c);
		c++;
		i++;
		if (!count && terminate > 0) printf(".");
		
	} 
	return i;
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
	if (!recursionCount) printf("\n");
	return i;
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

static int HandleDNSAnswer(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t* refsAndOffset, uint16_t ptrCount);

static int HandleDNSNSNames(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t* refsAndOffset, uint16_t ptrCount, int *found);

static int HandlePointerCondition(uint16_t* iter, uint16_t* ptr, uint16_t* referenceCounter);

static int HandleDNSAdditional(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t* refsAndOffset, uint16_t ptrCount);

static int ProcessBuffer();

static int ReadPointerForResponse(char* ptr, uint16_t* ptrs, uint16_t* pointerCount);

static void PrintIPv4(uint32_t addr);

static void PrintIPv6(char* addr);

static void PrintRecordHostname(char* ptr);

char* GetAddrByHostName(sockaddr_in *s, const char* str, int flags)
{

	if (!s || !str) return NULL;

	if (s->sin_family != AF_INET)
	{
		printf("Only IPv4 addresses to use for inital dns\n");
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

	do
	{
		PCSTR IPv4Decode = inet_ntop(dnsResolver.sin_family, &dnsResolver.sin_addr, helperstring, sizeof(helperstring));

		printf("Searching in IPv4 address %s\n", IPv4Decode);

		unsigned short ID = (rand() % (USHRT_MAX + 1));

		header->ID = htons(ID);
	
		int prevAnswer = AnswerCount;

		SOCKET ConnectionSocket = INVALID_SOCKET;

		ConnectionSocket = socket(dnsResolver.sin_family, SOCK_DGRAM, IPPROTO_UDP);

		if (ConnectionSocket == INVALID_SOCKET) {
			printf("Error at socket(): %ld\n", WSAGetLastError());
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
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectionSocket);
			return NULL;
		}

		printf("Bytes sent %ld\n", res);
			
		res = recv(ConnectionSocket, AnswerPool + AnswerCount, sizeof(AnswerPool)-AnswerCount, 0);
		if (res > 0) {
			printf("Bytes received: %d\n", res);
		}
		else if (res == 0)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());

		
		closesocket(ConnectionSocket);

		char* QueryHead = (char*)(AnswerPool + AnswerCount);

		AnswerCount += res;

		DNSHeader* headera = (DNSHeader*)(QueryHead);

		printf("Header ID: %hx\n", ntohs(headera->ID));
		printf("flags ID: %hx\n", ntohs(headera->flags));
		print_dns_flags(ntohs(headera->flags));
		printf("QDCOUNT ID: %hx\n", ntohs(headera->QDCOUNT));
		printf("ANCOUNT ID: %hx\n", ntohs(headera->ANCOUNT));
		printf("NSCOUNT ID: %hx\n", ntohs(headera->NSCOUNT));
		printf("ARCOUNT ID: %hx\n", ntohs(headera->ARCOUNT));

		int ret = PrintHostName((char*)(QueryHead + sizeof(DNSHeader)), QueryHead, 0);

		uint16_t rcode = ntohs(headera->flags) & 0xf;

		uint16_t answerCount = ntohs(headera->ANCOUNT);

		uint16_t nDomainCount = ntohs(headera->NSCOUNT);

		uint16_t adRecordCount = ntohs(headera->ARCOUNT);

		if (answerCount >= 1 && rcode == RCODE_NOERROR)
			found = 1;
		else if (answerCount == 0)
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
		
		PDNSRecordReference ref = (PDNSRecordReference)&RecordsBuffer[RecordsBufferCounter];
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

		for (uint16_t i = 0; i < answerCount; i++)
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
		
	} while (!found);	

	ProcessBuffer();

	AnswerCount = 0;
	QueryCount = 0;
	RecordsBufferCounter = 0;
	RecordsBufferReader = 0;

	return (char*)NULL;
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

static int ProcessBuffer()
{
	for (int j = RecordsBufferReader; j < RecordsBufferCounter;) {
		PDNSRecordReference ref = (PDNSRecordReference)&RecordsBuffer[j];
		if (!ref->visited) {
			ref->visited = 1;
			switch (ref->type)
			{
			case A:
			{
				PDNSARecord record = (PDNSARecord)&RecordsBuffer[j + sizeof(DNSRecordReference)];
				PDNSRecordReference aRef1 = (PDNSRecordReference)&RecordsBuffer[record->referenceHostNameRecordID];

				if (aRef1->type == QUERYHOSTNAME)
				{
					char* ptr = (char*)&RecordsBuffer[record->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					PrintRecordHostname(ptr);
				}

				int addr = record->addr;

				PrintIPv4(addr);

				break;
			}
			case CNAME:
			{
				PDNSCNAMERecord record = (PDNSCNAMERecord)&RecordsBuffer[j + sizeof(DNSRecordReference)];
				char* ptr = (char*)&RecordsBuffer[j + sizeof(DNSRecordReference) + sizeof(DNSCNAMERecord)];
				printf("Hostname : ");
				PrintRecordHostname(ptr);

				if (record->queryAlias != ~0ui16)
				{
					PDNSRecordReference aRef1 = (PDNSRecordReference)&RecordsBuffer[record->queryAlias];

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
					printf("Alias Hostname : ");
					PrintRecordHostname(ptr);
				}

				if (record->arecordcount)
				{
					for (uint16_t g = 0; g < record->arecordcount; g++)
					{
						PDNSRecordReference aRef1 = (PDNSRecordReference)&RecordsBuffer[record->arecordid[g]];
						aRef1->visited = 1;

						PDNSARecord aRef = (PDNSARecord)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						int addr = aRef->addr;
						PrintIPv4(addr);
					}
				}


				break;
			}
			case NS:

			{
				PDNSNSRecord record = (PDNSNSRecord)&RecordsBuffer[j + sizeof(DNSRecordReference)];
				char* ptr = (char*)&RecordsBuffer[j + sizeof(DNSRecordReference) + sizeof(DNSNSRecord)];
				printf("Hostname : ");
				PrintRecordHostname(ptr);

				if (record->arecordcount)
				{
					for (uint16_t g = 0; g < record->arecordcount; g++)
					{
						PDNSRecordReference aRef1 = (PDNSRecordReference)&RecordsBuffer[record->arecordid[g]];
						aRef1->visited = 1;

						if (aRef1->type == A)
						{
							PDNSARecord aRef = (PDNSARecord)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

							int addr = aRef->addr;
							PrintIPv4(addr);
						}
						else if (aRef1->type == AAAA) 
						{
							PDNSAAAARecord aRef = (PDNSAAAARecord)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];
							PrintIPv6(aRef->addr);
						}
						
					}
				}

				if (record->queryAlias != ~0ui16)
				{
					PDNSRecordReference aRef1 = (PDNSRecordReference)&RecordsBuffer[record->queryAlias];

					char* ptr = NULL;

					int off = 0;

					if (aRef1->type == QUERYHOSTNAME)
					{
						off = sizeof(DNSRecordReference);

					}

					ptr = (char*)&RecordsBuffer[record->queryAlias + off];
					printf("Alias Hostname : ");
					PrintRecordHostname(ptr);
				}

			}

			}
		}
		j += ref->size;
	}
	return 0;
}

static void PrintRecordHostname(char* ptr)
{
	while(*ptr)
	{
		printf("%c", *ptr++);
	}
	printf("\n");
}

static void PrintIPv4(uint32_t addr)
{
	printf("Address is : \n");
	for (int i = 0; i < 3; i++)
	{
		printf("%d.", ((addr & 0xff000000) >> 24));
		addr <<= 8;
	}
	printf("%d\n", ((addr & 0xff000000) >> 24));
}

static void PrintIPv6(char* addr)
{
	printf("Address is : \n");
	for (int i = 15; i > 0; i-=4)
	{
		for (int j = 0; j < 4 && (i - j) >= 1; j++)
		{
			printf("%x", addr[i]);
		}
		if (i > 4) printf(".");
	}
	printf("%x\n", addr[0]);
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
			PDNSRecordReference ref = (PDNSRecordReference)&RecordsBuffer[j];
			if (ref->offset == pointer)
			{
				printf("This is a reference to the %d response\n", i+1);
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

static int HandleDNSNSNames(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t *domainPtr, uint16_t ptrCount, int *found)
{
	char* ptr = RDDATA;


	printf("Type %hx\n", ntohs(answer->TYPE));
	printf("Class %hx\n", ntohs(answer->CLASS));
	printf("TTL %lx\n", ntohl(answer->TTL));
	printf("RDLENGTH %hx\n", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;
	PDNSRecordReference ref = (PDNSRecordReference)&RecordsBuffer[RecordsBufferCounter];
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
				printf("TOP LEVEL DOMAIN BEING SPECFIED: ");
				PrintHostName(topLevelDomain, queryHead, 0);
			}

			int move = PrintHostName(ptr, queryHead, 0);

			ptr += move;

			move = PrintHostName(ptr, queryHead, 0);

			ptr += move;

			printf("Serial is : %hu  \n", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			printf("Refresh is : %hu  \n", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			printf("Retry is : %hu  \n", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			printf("Expire is : %hu  \n", ntohs(*((uint16_t*)ptr)));
			ptr += 2;
			printf("Minimum is : %hu  \n", ntohs(*((uint16_t*)ptr)));
			ptr += 2;


			break;
		}
	}

	ref->size = RecordsBufferCounter - startReference;

	return len;
}

static int HandleDNSAnswer(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t* refsAndOffset, uint16_t ptrCount)
{
	char* ptr = RDDATA;


	printf("Type %hx\n", ntohs(answer->TYPE));
	printf("Class %hx\n", ntohs(answer->CLASS));
	printf("TTL %lx\n", ntohl(answer->TTL));
	printf("RDLENGTH %hx\n", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;


	PDNSRecordReference ref = (PDNSRecordReference)&RecordsBuffer[RecordsBufferCounter];
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

		PDNSARecord record = (PDNSARecord)&RecordsBuffer[RecordsBufferCounter];
		record->addr = addr;
		record->referenceHostNameRecordID = refsAndOffset[2];
		
		PrintIPv4(addr);

		DNSRecordReference *nameRef = (PDNSRecordReference)&RecordsBuffer[refsAndOffset[2]];

		if (nameRef->type == CNAME)
		{
			PDNSCNAMERecord record1 = (PDNSCNAMERecord)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}
		else if (nameRef->type == NS) {
			PDNSNSRecord record1 = (PDNSNSRecord)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}

		RecordsBufferCounter += sizeof(DNSARecord);
	}
	break;
	case CNAME:
	{
		PrintHostName(ptr, queryHead, 0);
		PDNSCNAMERecord record = (PDNSCNAMERecord)&RecordsBuffer[RecordsBufferCounter];
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
		PDNSNSRecord record = (PDNSNSRecord)&RecordsBuffer[RecordsBufferCounter];
		RecordsBufferCounter += sizeof(DNSNSRecord);
		record->namelength = WriteHostName(ptr, queryHead, 0, &RecordsBuffer[RecordsBufferCounter]);
		record->arecordcount = 0;
		record->queryAlias = refsAndOffset[2];
		RecordsBufferCounter += record->namelength;
		break;
	}
	default:
		printf("Unhandled response\n");
		break;

	}

	ref->size = RecordsBufferCounter - startReference;

	return len;
}

static int HandleDNSAdditional(DNSAnswer* answer, char* RDDATA, char* queryHead, uint16_t* refsAndOffset, uint16_t ptrCount)
{
	char* ptr = RDDATA;


	printf("Type %hx\n", ntohs(answer->TYPE));
	printf("Class %hx\n", ntohs(answer->CLASS));
	printf("TTL %lx\n", ntohl(answer->TTL));
	printf("RDLENGTH %hx\n", ntohs(answer->RDLENGTH));

	int startReference = RecordsBufferCounter;

	PDNSRecordReference ref = (PDNSRecordReference)&RecordsBuffer[RecordsBufferCounter];
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

		PDNSARecord record = (PDNSARecord)&RecordsBuffer[RecordsBufferCounter];
		record->addr = addr;
		record->referenceHostNameRecordID = refsAndOffset[2];


		PDNSRecordReference nameRef = (PDNSRecordReference)&RecordsBuffer[refsAndOffset[2]];

		if (nameRef->type == CNAME)
		{
			PDNSCNAMERecord record = (PDNSCNAMERecord)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record->arecordid[record->arecordcount++] = startReference;
		}
		else if (nameRef->type == NS) {
			PDNSNSRecord record1 = (PDNSNSRecord)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}

		RecordsBufferCounter += sizeof(DNSARecord);
	}
	break;
	case AAAA:
	{
		PDNSAAAARecord record = (PDNSAAAARecord)&RecordsBuffer[RecordsBufferCounter];
		record->referenceHostNameRecordID = refsAndOffset[2];
		for (int i = 0; i < len; i++)
		{
			record->addr[15-i] = (ptr[i] & 0xff);
		}

		PDNSRecordReference nameRef = (PDNSRecordReference)&RecordsBuffer[refsAndOffset[2]];

		if (nameRef->type == CNAME)
		{
			PDNSCNAMERecord record = (PDNSCNAMERecord)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record->arecordid[record->arecordcount++] = startReference;
		}
		else if (nameRef->type == NS) {
			PDNSNSRecord record1 = (PDNSNSRecord)&RecordsBuffer[refsAndOffset[2] + sizeof(DNSRecordReference)];
			record1->arecordid[record1->arecordcount++] = startReference;
		}

		RecordsBufferCounter += sizeof(DNSAAAARecord);
		break;

	}

	default:
		printf("Unhandled response\n");
		break;

	}

	ref->size = RecordsBufferCounter - startReference;

	return len;
}