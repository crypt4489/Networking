#include "DNSRoots.h"
#include <stdio.h>

char scratch[10 * 1024];

RootServers knownRootServers[MAX_SERVERS];

static int CreateKnownRoots(int size);

int ParseNamedRoot(const char* filename)
{
	FILE* fp = fopen(filename, "rb");

	if (!fp)
	{
		return -1;
	}

	fseek(fp, 0, SEEK_END);

	int size = ftell(fp);

	rewind(fp);

	if (size > (10 * 1024))
	{
		size = 10 * 1024;
	}

	if (!fread(scratch, 1, size, fp))
	{
		fclose(fp);
		return -1;
	};

	CreateKnownRoots(size);

	fclose(fp);

	return 0;
}

#define SKIPPLUS(seek, equal, maxLineIter, currIter) \
	do { \
		while (scratch[currIter] equal seek && (currIter++ != maxLineIter)); \
		if (maxLineIter == ++currIter) return -1; \
	} while(0) \

#define SKIP(seek, equal, maxLineIter, currIter) \
	do { \
		while (scratch[currIter] equal seek && (currIter++ != maxLineIter)); \
		if (maxLineIter == currIter) return -1; \
	} while(0) \



int ReadIPv4(RootServers* servPtr, int fileIter)
{
	for (int i = 0; i < 4; i++)
	{
		int num = 0;
		while (scratch[fileIter] != '.' && scratch[fileIter] != '\n' && scratch[fileIter] != ' ')
		{
			int lnum = scratch[fileIter] - '0';
			if (lnum > 9 || lnum < 0) return -1;
			num = (num * 10) + lnum;
			fileIter++;
		}
		fileIter++;
		if (num > 255 || num < 0) return -1;
		servPtr->ipv4addr <<= 8;
		servPtr->ipv4addr |= (num & 0xff);
	}

	return fileIter;
}

int ReadIPv6(RootServers* servPtr, int fileIter)
{
	SKIPPLUS('\n', != , fileIter + 256, fileIter);
	return fileIter;
}

static int CreateKnownRoots(int size)
{
	int knownRootIter = -1;
	int fileIter = 0;
	RootServers* servPtr = NULL;
	while (fileIter >= 0 && fileIter < size)
	{
		if (scratch[fileIter] == ';')
		{
		
			SKIPPLUS('\n', !=, fileIter + 256, fileIter);
		}
		else if (scratch[fileIter] == '.') // name
		{
			knownRootIter++;
			if (knownRootIter >= MAX_SERVERS) return 0;
			fileIter++;
			servPtr = &knownRootServers[knownRootIter];
			SKIP(' ', ==, fileIter + 256, fileIter);
			int ttl = 0;
			while (scratch[fileIter] != ' ')
			{
				int num = scratch[fileIter] - '0';
				if (num > 9 || num < 0) return -1;
				ttl = (ttl * 10) + num;
				fileIter++;
			}

			servPtr->ttl = ttl;

			SKIP(' ', ==, fileIter + 256, fileIter);
			SKIP(' ', != , fileIter + 256, fileIter);
			SKIP(' ', == , fileIter + 256, fileIter);

			int nameIter = 0;
			while (scratch[fileIter] != '\n')
			{
				servPtr->name[nameIter++] = scratch[fileIter++];
			}
			servPtr->name[nameIter] = 0;
			fileIter++;
		}
		else // address
		{
			if (!servPtr) return -1;
			int nameIter = 0;
			while (scratch[fileIter] != ' ')
			{
				if (servPtr->name[nameIter++] != scratch[fileIter++])
					return -1;
			}


			SKIP(' ', == , fileIter + 256, fileIter);
			int ttl = 0;
			while (scratch[fileIter] != ' ')
			{
				int num = scratch[fileIter] - '0';
				if (num > 9 || num < 0) return -1;
				ttl = (ttl * 10) + num;
				fileIter++;
			}

			if (ttl != servPtr->ttl)
				return -1;

			SKIP(' ', == , fileIter + 256, fileIter);

			int addrType = 0;
			for (int i = 0; i < 4; i++)
			{
				addrType <<= 8;
				addrType |= (0xff & scratch[fileIter++]);
			}
			SKIP(' ', == , fileIter + 256, fileIter);

			if (addrType == 0x41414141)
			{
				fileIter = ReadIPv6(servPtr, fileIter);
			}
			else if (addrType == 0x41202020)
			{
				fileIter = ReadIPv4(servPtr, fileIter);
			}
		}
	}
}