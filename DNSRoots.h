#pragma once

#define MAX_SERVERS 15

typedef struct root_servers_t
{
	char name[256];
	int ttl;
	int ipv4addr;
	char ipv6[16];
} RootServers;


extern RootServers knownRootServers[MAX_SERVERS];

int ParseNamedRoot(const char* filename);