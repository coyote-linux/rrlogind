// rrlogin.c - Routines to handle logging into the RR server
//
// Author:  Joshua Jackson  (jjackson@vortech.net)

#include "roadrunner.h"

int LoginResponse(struct rr_msg *msg)
{
   unsigned short *statuscode;
	struct rr_param *param;
	int LoginFailure = 1;

	if (!(param = ExtractParam(msg, RR_PARAM_STATUSCODE))) {
		syslog(LOG_INFO, "No status code parameter received in login response!\n");
		return LoginFailure;
	}

	statuscode = (unsigned short *) &param->data;

	switch (ntohs(*statuscode)) {
   	case 0: syslog(LOG_INFO,"Login successful for %s\n", UserName);
			LoginFailure = 0;
      	break;
      case 1: syslog(LOG_INFO, "Unknown Username: %s\n", UserName);
      	break;
      case 2: syslog(LOG_INFO, "Incorrect Password.\n");
      	break;
      case 3: syslog(LOG_INFO, "Account has been disabled.\n");
      	break;
      case 4: syslog(LOG_INFO, "You have been disabled?\n");
      	break;
      case 100: syslog(LOG_INFO, "Login for %s successful, but you are already logged in.\n", UserName);
			LoginFailure = 0;
      	break;
      case 101: syslog(LOG_INFO, "Login Authenticate Retry Exceeded.");
      	break;
      case 102: syslog(LOG_INFO, "Login for %s successful, but software is out of date.\n", UserName);
			LoginFailure = 0;
      	break;
      case 103: syslog(LOG_INFO, "Invalid client software version.\n");
      	break;
      case 500: syslog(LOG_INFO, "The login server is currently hosed.\n");
      	break;
      case 501: syslog(LOG_INFO, "The server is unable to validate the username: %s\n", UserName);
      	break;
      case 502: syslog(LOG_INFO, "The server is unable to validate password for %s.\n", UserName);
      	break;
     	default: syslog(LOG_INFO, "Unknow status code received from server.\n");
   }

	// Also log any text returned from server
	if ((param = ExtractParam(msg, RR_PARAM_RESPTEXT))) {
		// Ensure string sanity
		param->data[ntohs(param->param_len) - 4] = '\0';
		syslog(LOG_INFO, "Server response text: %s",	(char *) &param->data);
	}

	return LoginFailure;
}

int ValidateLoginServerResponse (struct rr_msg *msg)
{
	char *hashbuff;
	int	buffsize, buffindex;
	char	MsgHash[16], CalcHash[16];
	struct rr_param *Param;
	unsigned short MsgType;

	// Extract the login hash parameter
	if (!(Param = ExtractParam(msg, RR_PARAM_LOGINHASH))) {
		// If we're missing a hash parameter, the login message can not be
		// verified as authentic... not much we can do at this point
		syslog(LOG_INFO, "Login hash parameter missing from login reponse!\n");
		// We need to return an "OK" for some busted auth servers
		if (AlwaysTrust)
			return 1;
		else
			return 0;
	}
	memcpy(&MsgHash, &Param->data, 16);

	// deduct the size of the command header and the hash parameter
	buffsize = ntohs(msg->header.msg_len) - 28;
	// Add the length of the Nonce, Password and MsgType
	hashbuff = malloc(buffsize + 34);
	buffindex = 0;
	memcpy(hashbuff, &Nonce, 16);
	memcpy(hashbuff + 16, &HashedPW, 16);
	memcpy(hashbuff + 32, &msg->data, buffsize);
	MsgType = htons(RR_MSG_LOGIN_RESP);
	memcpy(hashbuff + 32 + buffsize, &MsgType, 2);
   md5_buffer(hashbuff, buffsize + 34, &CalcHash);
	free(hashbuff);

	if (!memcmp(&CalcHash, &MsgHash, 16))
		return 1;
	else
		return 0;
}

int LoginRequest(int sockfd, int ListenPort)
{
   char Credentials[16];
   long int Blinding;
	unsigned short StatusPort;
	struct rr_msg *LoginMsg;
	struct rr_param *Param;
	unsigned short sidx, slen;
	char *s;
	
   // Construct a login request packet
	LoginMsg = NewMsg(RR_MSG_LOGIN_REQ);
	AddParam(&LoginMsg, RR_PARAM_USERNAME, UserName, strlen(UserName));
	AddShortParam(&LoginMsg, RR_PARAM_CLIENTVER, Version_ID);
	AddParam(&LoginMsg, RR_PARAM_OSID, OS_ID, strlen(OS_ID));
	AddParam(&LoginMsg, RR_PARAM_OSVER, OS_Version, strlen(OS_Version));
	AddShortParam(&LoginMsg, RR_PARAM_REASON, 0);
	AddShortParam(&LoginMsg, RR_PARAM_REQPORT, ListenPort);
	// Send the request to the server
   write(sockfd, LoginMsg, ntohs(LoginMsg->header.msg_len));
	// Dispose of the request
	free(LoginMsg);

	// Allocate enough (hopefully) space for the response
	LoginMsg = malloc(16384);
   if (!read(sockfd, LoginMsg, 16384)) {
		free(LoginMsg);
   	syslog(LOG_INFO, "No response from login server.");
      return RR_STATE_ABORT;
	}

   if (ntohs(LoginMsg->header.msg_type) == RR_MSG_LOGIN_RESP) {
   	LoginResponse(LoginMsg);
		free(LoginMsg);
      return RR_STATE_ABORT;
   } else if (ntohs(LoginMsg->header.msg_type) != RR_MSG_AUTH_RESP) {
   	syslog(LOG_INFO, "Got unexpected message type: %i from server.",
				 ntohs(LoginMsg->header.msg_type));
		free(LoginMsg);
      return RR_STATE_ABORT;
   }

	if (!(Param = ExtractParam(LoginMsg, RR_PARAM_HASH))) {
		syslog(LOG_INFO, "Hash parameter missing from reponse, bailing out.");
		free(LoginMsg);
	   return RR_STATE_ABORT;
	}
	if (!( *(unsigned short *)&Param->data )) {
     // Request to send a plain text password - not supported
	  syslog(LOG_INFO, "Got request for clear-text password... not supported.");
  	  free(LoginMsg);
     return RR_STATE_ABORT;
   }

	// Set our session Nonce
	if (!(Param = ExtractParam(LoginMsg, RR_PARAM_NONCE))) {
		syslog(LOG_INFO, "Nonce parameter missing from reponse, bailing out.");
		free(LoginMsg);
	   return RR_STATE_ABORT;
	}
	memcpy(&Nonce, &Param->data, 16);

	free(LoginMsg);

	// Get the "Blinding" timestamp
   Blinding = time(NULL);
   BuildCredentials(&Credentials, &Nonce, Blinding, RR_MSG_AUTHLOGIN_REQ);

	// Build the login_auth message
	LoginMsg = NewMsg(RR_MSG_AUTHLOGIN_REQ);
	AddParam(&LoginMsg, RR_PARAM_CREDS, &Credentials, 16);
	AddLongParam(&LoginMsg, RR_PARAM_BLINDING, Blinding);

	// Send the request to the server
   write(sockfd, LoginMsg, ntohs(LoginMsg->header.msg_len));
	free(LoginMsg);

	// Allocate enough (hopefully) space for the response
	LoginMsg = malloc(16384);
   if (!read(sockfd, LoginMsg, 16384)) {
   	syslog(LOG_INFO, "No response from login server.");
		free(LoginMsg);
      return RR_STATE_ABORT;
	}

   if (ntohs(LoginMsg->header.msg_type) != RR_MSG_LOGIN_RESP) {
   	syslog(LOG_INFO, "Got unexpected message type: %i from server.",
				 ntohs(LoginMsg->header.msg_type));
		free(LoginMsg);
      return RR_STATE_ABORT;
   }

	if (LoginResponse(LoginMsg)) {
		free(LoginMsg);
		return RR_STATE_ABORT;
	}

	if (!ValidateLoginServerResponse(LoginMsg)) {
		syslog(LOG_INFO, "Invalid login hash parameter!");
		free(LoginMsg);
		return RR_STATE_ABORT;
	}

	// Get the logout port parameter and update the logout server list
	if (!(Param = ExtractParam(LoginMsg, RR_PARAM_LOGOUTPORT))) {
		// Logout port default already set by protocol negotiation
		syslog(LOG_INFO, "Logout port parameter missing from reponse, using default.");
	} else {
		// Since the protocol specs only detail having 1 logout host, we will
		// not attempt to walk the linked list.
		logout_servers->serveraddr.sin_port = *(unsigned short *)&Param->data;
	}

	// Get the status port parameter and update the logout server list
	if (!(Param = ExtractParam(LoginMsg, RR_PARAM_STATUSPORT))) {
		//	Use the same port that is used for logins
		syslog(LOG_INFO, "Status port parameter missing from reponse, using default.");
		StatusPort = login_servers->serveraddr.sin_port;
	} else {
		StatusPort = *(unsigned short *)&Param->data;
	}

	// Get the logout port parameter and update the logout server list
	if (!(Param = ExtractParam(LoginMsg, RR_PARAM_TRUSTEDSERVERS))) {
		syslog(LOG_INFO, "Trusted servers list missing, using default.");
		AddServer(&trusted_servers, login_servers->servername, ntohs(StatusPort));
	} else {
		// Since the list of trusted servers can contain more than 1 server
		// in a comma delimited string, we have to do some parsing
		s = (char *) &Param->data;
		slen = ntohs(Param->param_len) - 4;
		for (sidx = 0; sidx < strlen(s); sidx++) {
			if (s[sidx] == ',')
				s[sidx] = '\0';
		}
		sidx = 0;
		while (sidx < slen) {
			AddServer(&trusted_servers, s, StatusPort);
			sidx += (strlen(s) + 1);
			s += sidx;
		}
	}

	free(LoginMsg);
   return RR_STATE_IDLE;
}

int RRLogin(int ListenPort)
{
 	int sockfd;
   int result;

   // Connect to the server
	sockfd = RRConnect(login_servers);
   if (sockfd < 0) {
   	syslog(LOG_INFO, "Unable to connect to server: %m");
      return RR_STATE_RETRY;
   } else if (SignalState) {
		return RR_STATE_INTR;
	}

	result = LoginRequest(sockfd, ListenPort);

	close(sockfd);

   return result;

}

