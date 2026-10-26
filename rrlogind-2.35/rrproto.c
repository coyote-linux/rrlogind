// rrlogin.c - Routines to handle protocol negotiation
//
// Author:  Joshua Jackson  (jjackson@vortech.net)
#include "roadrunner.h"

int ProtoResponse(struct rr_msg *msg)
{
   unsigned short *statuscode;
	struct rr_param *param;
	int ProtoFailure = 1;

	if (!(param = ExtractParam(msg, RR_PARAM_STATUSCODE))) {
		syslog(LOG_INFO, "No status code parameter recieved!\n");
		return ProtoFailure;
	}

	statuscode = (unsigned short *) &param->data;

   //memcpy(&statuscode, &msg[12], 2);

	switch (ntohs(*statuscode)) {
   	case 0: syslog(LOG_INFO,"Protocol negotiation successful.");
			ProtoFailure = 0;
      	break;
      case 300: syslog(LOG_INFO, "Protocol negotiation successful, but software is out of date.");
			ProtoFailure = 0;
      	break;
      case 301: syslog(LOG_INFO, "Protocol negotiation failure, invalid client version.");
      	break;
      case 302: syslog(LOG_INFO, "Protocol negotiation failure, invalid request.");
      	break;
      case 500: syslog(LOG_INFO, "The login server is currently hosed.");
      	break;
     	default: syslog(LOG_INFO, "Unknow status code received from server.");
   }

	// Also log any text returned from server
	if ((param = ExtractParam(msg, RR_PARAM_RESPTEXT))) {
		// Ensure string sanity
		param->data[ntohs(param->param_len) - 4] = '\0';
		syslog(LOG_INFO, "Server response text: %s",	(char *) &param->data);
	}

	return ProtoFailure;
}

int RRProtoNegRequest(int sockfd)
{
	struct rr_msg *ProtoMsg;
	struct rr_param *Param;
	char *server_name;
	unsigned short server_port;
	
   // Construct a login request packet
	ProtoMsg = NewMsg(RR_MSG_PROTONEG_REQ);
	AddShortParam(&ProtoMsg, RR_PARAM_CLIENTVER, Version_ID);
	AddParam(&ProtoMsg, RR_PARAM_OSID, OS_ID, strlen(OS_ID));
	AddParam(&ProtoMsg, RR_PARAM_OSVER, OS_Version, strlen(OS_Version));
	AddShortParam(&ProtoMsg, RR_PARAM_PROTOLIST, RR_PROTO_CHALLENGE);
	// Send the request to the server
   write(sockfd, ProtoMsg, ntohs(ProtoMsg->header.msg_len));
	// Dispose of the request
	free(ProtoMsg);

	// Allocate enough (hopefully) space for the response
	ProtoMsg = malloc(16384);
   if (!read(sockfd, ProtoMsg, 16384)) {
   	syslog(LOG_INFO, "No response from login server.");
      return RR_STATE_ABORT;
	}

   if (ntohs(ProtoMsg->header.msg_type) != RR_MSG_PROTONEG_RESP) {
   	syslog(LOG_INFO, "Got unexpected message type: %i from server.",
				 ntohs(ProtoMsg->header.msg_type));
		free(ProtoMsg);
      return RR_STATE_ABORT;
   }

	if (ProtoResponse(ProtoMsg)) {
     	// An error has occurred
	  	syslog(LOG_INFO, "Protocol negotiation failure.");
  	  	free(ProtoMsg);
		return RR_STATE_ABORT;
	}

	// Check the server selected protocol
	if (!(Param = ExtractParam(ProtoMsg, RR_PARAM_PROTOSEL))) {
		syslog(LOG_INFO, "Protocol selection parameter missing, bailing out.");
		free(ProtoMsg);
	   return RR_STATE_ABORT;
	}
	if (ntohs(*(unsigned short *)&Param->data) != RR_PROTO_CHALLENGE) {
		syslog(LOG_INFO, "Unsupported protocol selection returned from server.");
		free(ProtoMsg);
	   return RR_STATE_ABORT;
	}

	// Extract the login server parameter from the message
	if (!(Param = ExtractParam(ProtoMsg, RR_PARAM_LOGINHOST))) {
		syslog(LOG_INFO, "No login servers specified in protocol negotiation, using default.");
		server_name = (char *)&session_servers->servername;
	} else {
		// extract the login server address
		server_name = (char *)&Param->data;
	}

	if (!(Param = ExtractParam(ProtoMsg, RR_PARAM_LOGINPORT))) {
		syslog(LOG_INFO, "No login port specified in protocol negotiation, using default.");
		server_port = ntohs(session_servers->serveraddr.sin_port);
	} else {
		// extract the login server's port
		server_port = ntohs(*(unsigned short *)&Param->data);
	}
	// Add the login server to the list
	AddServer(&login_servers, server_name, server_port);
	// Since the protocol only dictates that the logout PORT can change, we
	// will also add it to the logout server list and change the port later
	AddServer(&logout_servers, server_name, server_port);
	
	free(ProtoMsg);
	// Protocol negotiation successful, ready for login
	return RR_STATE_LOGIN;
	
}

int RRProtoNeg()
{
 	int sockfd;
   int result;

   // Connect to the server
	sockfd = RRConnect(session_servers);
   if (sockfd < 0) {
   	syslog(LOG_INFO, "Unable to connect to server: %m");
      return RR_STATE_RETRY;
   }

	result = RRProtoNegRequest(sockfd);

	close(sockfd);

   return result;

}

