#pragma once
#include <winsock2.h>

SOCKET CreateSocket(int af, int type, int protocol);
int ConnectSocket(SOCKET socket, sockaddr* struct_addr, int size);