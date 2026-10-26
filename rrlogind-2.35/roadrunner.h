/* roadrunner.h
 *
 * Road Runner protocol specific declarations
 *
 * Author: Joshua Jackson   (jjackson@vortech.net)
 *
 */

#ifndef _ROADRUNNER_H
#define _ROADRUNNER_H 1

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/utsname.h>
#include <rrconf.h>
#include "md5.h"

#define RRLOGIND_VERSION "v2.35"

// Client state declarations
#define RR_STATE_IDLE 0
#define RR_STATE_PROTONEG 1
#define RR_STATE_LOGIN 2
#define RR_STATE_LOGOUT 3
#define RR_STATE_LISTENER 4
#define RR_STATE_ABORT 5
#define RR_STATE_INTR 6
#define RR_STATE_DONE 7
#define RR_STATE_RETRY 8

// Road Runner Message Request Types
#define RR_MSG_PROTONEG_REQ 1
#define RR_MSG_LOGIN_REQ 3
#define RR_MSG_AUTHLOGIN_REQ 4
#define RR_MSG_LOGOUT_REQ 6
#define RR_MSG_AUTHLOGOUT_REQ 7
#define RR_MSG_AUTH_REQ 10
#define RR_MSG_STATUS_REQ 11
#define RR_MSG_RESTART_REQ 13
// Road Runner Message Response Types
#define RR_MSG_PROTONEG_RESP 2
#define RR_MSG_LOGIN_RESP 5
#define RR_MSG_LOGOUT_RESP 8
#define RR_MSG_AUTH_RESP 9
#define RR_MSG_STATUS_RESP 12

// Road Runner Protocol Type Definitions
#define RR_PROTO_RESERVED 0
#define RR_PROTO_CHALLENGE 1
// Road Runner Message Parameter Definitions
#define RR_PARAM_RESERVED 0
#define RR_PARAM_PROTOLIST 1
#define RR_PARAM_PROTOSEL 2
#define RR_PARAM_CLIENTVER 3
#define RR_PARAM_OSID 4
#define RR_PARAM_OSVER 5
#define RR_PARAM_REASON 6
#define RR_PARAM_USERNAME 7
#define RR_PARAM_REQPORT 8
#define RR_PARAM_RESPTEXT 9
#define RR_PARAM_STATUSCODE 10
#define RR_PARAM_CREDS 11
#define RR_PARAM_NONCE 12
#define RR_PARAM_SEQNUM 13
#define RR_PARAM_HASH 14
#define RR_PARAM_LOGINPORT 15
#define RR_PARAM_LOGOUTPORT 16
#define RR_PARAM_STATUSPORT 17
#define RR_PARAM_SUSPEND 18
#define RR_PARAM_STATUSAUTH 19
#define RR_PARAM_RESTARTAUTH 20
#define RR_PARAM_BLINDING 21
#define RR_PARAM_TRUSTEDSERVERS 22
#define RR_PARAM_LOGINHASH 23
#define RR_PARAM_LOGINHOST 24

#define CreateBlinding htonl(time(NULL))

struct rr_server_list {
	char	servername[255];
	struct sockaddr_in serveraddr;
	struct rr_server_list *next;
};

struct rr_common_header {
	unsigned short	msg_type;
   unsigned short msg_len;
   unsigned long session_id;
};

struct rr_msg {
	struct rr_common_header header;
   char data[32768];
};

struct rr_param {
	unsigned short	param_type;
   unsigned short param_len;
	char data[16384];
};

// Global Session Parameters
// rrlogind.c
extern int Version_ID;
extern char OS_ID[257];
extern char OS_Version[257];
extern int SignalState;

// Application Parameters
extern int DebugFlag;
extern int VerboseFlag;
extern int KeepAliveMonitor;
extern int AlwaysTrust;  // To compensate for busted auth servers

// Session parameters
extern char Nonce[16];
extern char UserName[21];
extern char HashedPW[16];

extern struct rr_server_list *session_servers;
extern struct rr_server_list *login_servers;
extern struct rr_server_list *logout_servers;
extern struct rr_server_list *trusted_servers;

// External Function
// rrproto.c
extern int RRProtoNeg();
// rrlogin.c
extern int RRLogin(int ListenPort);
// rrlogout.c
extern int RRLogout();
// rrcomm.c
extern int RRConnect();
extern int RRListen(unsigned short *listenport);
extern void AddServer(struct rr_server_list **server_list, char *servername,
							unsigned short port);
// rrstatus.c
extern int CheckRequests(int ListenSock);
extern int RRHandleRequest(int ListenSock);
// rrauth.c
extern void BuildCredentials(void *Creds, void *nonce, long int Blinding,
                             unsigned short msgtype);
extern struct rr_msg *NewMsg(unsigned short MsgType);
extern void AddParam(struct rr_msg **RRMsg, int ParamType, void *ParamData,
				  			int ParamLen);
extern void AddShortParam(struct rr_msg **RRMsg, int ParamType,
		 						 unsigned short ParamData);
extern void AddLongParam(struct rr_msg **RRMsg, int ParamType,
								 unsigned long ParamData);
extern struct rr_param *ExtractParam(struct rr_msg *RRMsg, int ParamType);
// daemon.c
extern void DaemonInit(const char *pidfile);
extern void KillCurProc(char *pidfile);

#endif
