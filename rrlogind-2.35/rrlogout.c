// rrlogout.c - Handled road runner logouts
//
// Author: Joshua Jackson  (jjackson@vortech.net)
//
#include "roadrunner.h"

void LogoutResponse(struct rr_msg *msg)
{
   unsigned short *statuscode;
	struct rr_param *param;

	if (!(param = ExtractParam(msg, RR_PARAM_STATUSCODE))) {
		syslog(LOG_INFO, "No status code parameter recieved in logout response!\n");
		return;
	}

	statuscode = (unsigned short *) &param->data;

	switch (ntohs(*statuscode)) {
   	case 0: syslog(LOG_INFO, "Logout for %s successful.", UserName);
      	break;
      case 1: syslog(LOG_INFO, "Unknown Username: %s", UserName);
      	break;
      case 2: syslog(LOG_INFO, "Incorrect password for %s", UserName);
      	break;
      case 3: syslog(LOG_INFO, "Account has been disabled.");
      	break;
      case 4: syslog(LOG_INFO, "You have been disabled?");
      	break;
      case 200: syslog(LOG_INFO, "Logout for %s successful, but you are already logged out.", UserName);
      	break;
      case 201: syslog(LOG_INFO, "Logout Authenticate Retry Exceeded.");
      	break;
      case 500: syslog(LOG_INFO, "The login server is currently hosed.");
      	break;
      case 501: syslog(LOG_INFO, "The server is unable to validate your username.");
      	break;
      case 502: syslog(LOG_INFO, "The server is unable to validate your password.");
      	break;
     	default: syslog(LOG_INFO, "Unknow status code received from server.");
   }
}

int LogoutRequest(int sockfd)
{
   char Credentials[16];
	long int Blinding;

	struct rr_msg *LogoutMsg;

   // Construct a login request packet
	LogoutMsg = NewMsg(RR_MSG_LOGOUT_REQ);
	AddParam(&LogoutMsg, RR_PARAM_USERNAME, UserName, strlen(UserName));
	AddShortParam(&LogoutMsg, RR_PARAM_CLIENTVER, Version_ID);
	AddParam(&LogoutMsg, RR_PARAM_OSID, OS_ID, strlen(OS_ID));
	AddParam(&LogoutMsg, RR_PARAM_OSVER, OS_Version, strlen(OS_Version));
	AddShortParam(&LogoutMsg, RR_PARAM_REASON, 0);
	// Send the request to the server
   write(sockfd, LogoutMsg, ntohs(LogoutMsg->header.msg_len));
	// Dispose of the request
	free(LogoutMsg);


	// Allocate enough (hopefully) space for the response
	LogoutMsg = malloc(16384);
   if (!read(sockfd, LogoutMsg, 16384)) {
		free(LogoutMsg);
   	syslog(LOG_INFO, "No response from logout server.");
      return RR_STATE_ABORT;
	}

   if (ntohs(LogoutMsg->header.msg_type) == RR_MSG_LOGOUT_RESP) {
   	LogoutResponse(LogoutMsg);
		free(LogoutMsg);
      return RR_STATE_ABORT;
   } else if (ntohs(LogoutMsg->header.msg_type) != RR_MSG_AUTH_RESP) {
   	syslog(LOG_INFO, "Got unexpected message type: %i from server.",
				 ntohs(LogoutMsg->header.msg_type));
		free(LogoutMsg);
      return RR_STATE_ABORT;
   }

	// Get the "Blinding" timestamp
   Blinding = time(NULL);
   BuildCredentials(&Credentials, &Nonce, Blinding, RR_MSG_AUTHLOGOUT_REQ);
	// Build the logout_auth message
	LogoutMsg = NewMsg(RR_MSG_AUTHLOGOUT_REQ);
	AddParam(&LogoutMsg, RR_PARAM_CREDS, &Credentials, 16);
	AddLongParam(&LogoutMsg, RR_PARAM_BLINDING, Blinding);
	// Send the request to the server
   write(sockfd, LogoutMsg, ntohs(LogoutMsg->header.msg_len));
	free(LogoutMsg);

	// Allocate enough (hopefully) space for the response
	LogoutMsg = malloc(16384);
   if (!read(sockfd, LogoutMsg, 16384)) {
   	syslog(LOG_INFO, "No response from login server.");
		free(LogoutMsg);
      return RR_STATE_ABORT;
	}

   if (ntohs(LogoutMsg->header.msg_type) != RR_MSG_LOGOUT_RESP) {
   	syslog(LOG_INFO, "Got unexpected message type: %i from server.\n",
				 ntohs(LogoutMsg->header.msg_type));
		free(LogoutMsg);
      return RR_STATE_ABORT;
   }

	LogoutResponse(LogoutMsg);
	free(LogoutMsg);
   return RR_STATE_IDLE;
}

int RRLogout()
{
 	int sockfd;

   if (!(sockfd = RRConnect(logout_servers))) {
   	syslog(LOG_INFO, "Unable to connect to server: %m");
     	return RR_STATE_ABORT;
   } else if (SignalState) {
		// If we catch any signals during a logout, abort to avoid looping
		return RR_STATE_ABORT;
	}

	LogoutRequest(sockfd);

   close(sockfd);

	// Seems stupid... but logouts only occur when killing rrlogind so
	// an abort at this point will not cause a premature termination of the
	// daemon.
	return RR_STATE_ABORT;
}

