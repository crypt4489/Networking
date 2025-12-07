#include "ConnectionSocket.h"

#define ERROR_LOG_LVL 1
#define DEBUG_LOG_LVL 2
#define INFO_LOG_LVL 3

#define CONN_LOG_LVL 1

#define STRINGIFY_IMPL(X) #X
#define STRINGIFY(X) STRINGIFY_IMPL(X)

#if defined(INFO_LOG_LVL) && CONN_LOG_LVL >= INFO_LOG_LVL
#define INFOLOG(fmt, ...) \
        (printf("INFO : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else 
#define INFOLOG(fmt, ...)
#endif

#if defined(DEBUG_LOG_LVL) && CONN_LOG_LVL >= DEBUG_LOG_LVL
#define DEBUGLOG(fmt, ...)  \
        (printf("DEBUG : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else
#define DEBUGLOG(fmt, ...)
#endif


#if  defined(ERROR_LOG_LVL) && CONN_LOG_LVL >= ERROR_LOG_LVL
#define ERRORLOG(fmt, ...) \
        (printf("ERROR : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else
#define ERRORLOG(fmt, ...)
#endif



SOCKET CreateSocket(int af, int type, int protocol)
{
	SOCKET ConnectionSocket = INVALID_SOCKET;

	ConnectionSocket = socket(af, type, protocol);

	if (ConnectionSocket == INVALID_SOCKET) {
		DEBUGLOG("Error at socket(): %ld", WSAGetLastError());
	}

	return ConnectionSocket;
}
int ConnectSocket(SOCKET socket, sockaddr* struct_addr, int size)
{
	int res = connect(socket, struct_addr, size);

	return res;
}