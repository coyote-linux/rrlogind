// rrstatus.c   - Handles server auth status and session restarts
//
// Author: Joshua Jackson   (jjackson@vortech.net)

#include "roadrunner.h"

// Status based globals
int PacketSequence = 0;
int KeepAliveInterval = 0;
int LastKeepAlive = 0;

//------------------------------------------------------------
// RRAuthReq()
//
// Responds to a request for session verification from the
// server
int RRAuthReq(struct rr_msg *RRMsg, int ListenSock, struct sockaddr_in *addr)
{
   char Credentials[16];
	struct rr_msg *AuthMsg;

	if (DebugFlag)
		fprintf(stderr, "Got AuthStatus Request from server.\n");

	if (VerboseFlag || DebugFlag)
		syslog(LOG_INFO, "Got Keep Alive Request from server.\n");

   if (ntohs(RRMsg->header.msg_type) != RR_MSG_STATUS_REQ) {
   	syslog(LOG_INFO, "Got unexpected message type: %i from server.",
				ntohs(RRMsg->header.msg_type));
		return RR_STATE_ABORT;
   }

	PacketSequence ++;
	BuildCredentials(&Credentials, &Nonce, PacketSequence, RR_MSG_STATUS_RESP);

	AuthMsg = NewMsg(RR_MSG_STATUS_RESP);
	AddShortParam(&AuthMsg, RR_PARAM_STATUSCODE, 0);
	AddParam(&AuthMsg, RR_PARAM_STATUSAUTH, &Credentials, 16);
	AddLongParam(&AuthMsg, RR_PARAM_SEQNUM, PacketSequence);

   if (sendto(ListenSock, AuthMsg, 42, 0,
			(struct sockaddr *) addr, sizeof(struct sockaddr_in)) < 0) {
				syslog(LOG_INFO, "Error sending keepalive packet: %m");
	}

	free(AuthMsg);

	// If KeepAliveInterval has not been set, then LastKeepAlive contains
	// the time at which we first started listening for keep alives.
	if (KeepAliveMonitor) {
		if (!KeepAliveInterval) {
			// Calculate the time that has passed and give the server an extra
			// 5 minutes.
			KeepAliveInterval = time(NULL) - LastKeepAlive + 300;
		}
		LastKeepAlive = time(NULL);
	}

	return RR_STATE_IDLE;
}

//------------------------------------------------------------
// RRRestartReq()
//
// Verify the credentials of the system requesting a session
// restart
int RRRestartReq(struct rr_msg *RRMsg)
{
   char Credentials[16];
   char CalcCreds[16];
   long int Blinding;
	struct rr_param *Param;

	syslog(LOG_INFO, "Got Session Restart Request from server.");


   if (ntohs(RRMsg->header.msg_type) != RR_MSG_RESTART_REQ) {
   	syslog(LOG_INFO, "Got unexpected message type: %i from server.",
				 ntohs(RRMsg->header.msg_type));
		return RR_STATE_ABORT;
   }

	if (!(Param = ExtractParam(RRMsg, RR_PARAM_RESTARTAUTH))) {
	   syslog(LOG_INFO, "Malformed restart request received!");
		return RR_STATE_IDLE;
	}

	memcpy(&Credentials, &Param->data, 16);

	if (!(Param = ExtractParam(RRMsg, RR_PARAM_BLINDING))) {
	   syslog(LOG_INFO, "Malformed restart request received!");
		return RR_STATE_IDLE;
	}
   memcpy(&Blinding, &Param->data, 4);

   BuildCredentials(&CalcCreds, &Nonce, ntohl(Blinding), RR_MSG_RESTART_REQ);

   if (!memcmp(&Credentials, &CalcCreds, 16)) {
		// Reset the keep alive timers
		KeepAliveInterval = 0;
		LastKeepAlive = 0;
	 	return RR_STATE_LOGIN;
	} else {
	   syslog(LOG_INFO, "Unauthorized restart request received!");
		return RR_STATE_IDLE;
	}
}

//------------------------------------------------------------
// ValidateRequestServer()
//
// Determines if the connecting host is an authorized session
// management server.
int ValidateRequestServer(struct sockaddr_in *addr)
{
	struct rr_server_list *server = trusted_servers;

	while (server) {
		if (!memcmp(&addr->sin_addr, &server->serveraddr.sin_addr,
			sizeof(struct in_addr)))
				return 1;
		server = server->next;
	}
	
	return 0;
}

//------------------------------------------------------------
// HandleRequest()
//
// Determines what the server wants and returns the proper
// ClientState value
int RRHandleRequest(int ListenSock)
{
	struct sockaddr_in sockaddr;
	int slen;
   struct rr_msg *RRMsg;
	int Result;

	RRMsg = malloc(16384);

	slen = sizeof(struct sockaddr_in);
	
	if (recvfrom(ListenSock, RRMsg, 16384, 0,(struct sockaddr *) &sockaddr, &slen) < 0) {
   	syslog(LOG_INFO, "Error Reading From Socket: %m");
		free(RRMsg);
		return RR_STATE_ABORT;
	}

	if (!ValidateRequestServer(&sockaddr)) {
		syslog(LOG_INFO, "Unauthorized connection from: %s", inet_ntoa(sockaddr.sin_addr));
		free(RRMsg);
		return RR_STATE_IDLE;
	}

	switch (ntohs(RRMsg->header.msg_type)) {
		case RR_MSG_STATUS_REQ:
			Result = RRAuthReq(RRMsg, ListenSock, &sockaddr);
			break;
		case RR_MSG_RESTART_REQ:
			Result =	RRRestartReq(RRMsg);
			break;
		default:
  			syslog(LOG_INFO, "Garbage data received on listener socket.");
			Result = RR_STATE_IDLE;
			break;
	}

	free(RRMsg);
	return Result;
}

//------------------------------------------------------------
// CheckRequests() -	Watches the listener socket for incoming
//							status requests and lost keep alives
int CheckRequests(int ListenSock)
{
 	fd_set SrvReqSet;
   struct timeval tv;
   int ret;

	// If the keep alive interval has been determined, check to see if we have
	// missed one.
	if (KeepAliveMonitor) {
		if (KeepAliveInterval) {
			if ((time(NULL) - LastKeepAlive) > KeepAliveInterval) {
				syslog(LOG_INFO, "Keep alive packet missed, restarting session.");
				KeepAliveInterval = 0;
				LastKeepAlive = 0;
				return RR_STATE_LOGIN;
			}
		} else {
			// Interval has not been determined, if we have not marked our start
			// time, do it now.
			if (!LastKeepAlive)
				LastKeepAlive = time(NULL);
		}
	}
	
   FD_ZERO (&SrvReqSet);
   FD_SET (ListenSock, &SrvReqSet);

   tv.tv_sec = 30;
   tv.tv_usec = 0;
   if ((ret = select(ListenSock + 1, &SrvReqSet, NULL, NULL, &tv)) < 0) {
     	if (errno != EINTR) {
        	syslog(LOG_INFO, "Error listening for server: %m");
         return RR_STATE_ABORT;
      } else
			return RR_STATE_INTR;
	}
  	if (ret == 1) {
     	return RR_STATE_LISTENER;
   } else
  		return RR_STATE_IDLE;
}

