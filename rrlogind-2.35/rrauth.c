// rrauth.c  -  Auth calculations routines and message handling
//
// Author: Joshua Jackson		(jjackson@vortech.net)
//
#include "roadrunner.h"

//------------------------------------------------------------
// BuildCredentials() -	Builds a RR Protocol Specific Credentials
//								record.
void BuildCredentials(void *Creds, void *nonce, long int Blinding,
                      unsigned short msgtype)
{
 	char CredsBuff[39];
   unsigned short NetMsg = htons(msgtype);

	Blinding = htonl(Blinding);
   memset(CredsBuff, 0, sizeof(CredsBuff));
   memcpy(&CredsBuff[0], nonce, 16);
   memcpy(&CredsBuff[16], &HashedPW, 16);
   memcpy(&CredsBuff[32], &Blinding, 4);
   memcpy(&CredsBuff[36], &NetMsg, 2);
   md5_buffer(&CredsBuff[0], 38, Creds);

}

//------------------------------------------------------------
// NewMsg() - Returns a new Road Runner message
//
//
struct rr_msg *NewMsg(unsigned short MsgType)
{
	struct rr_msg *NewMsg;

	NewMsg = malloc(sizeof(struct rr_common_header));

	if (NewMsg) {
		NewMsg->header.msg_len = htons(8);
		NewMsg->header.msg_type = htons(MsgType);
		NewMsg->header.session_id = 0;
	}

	return NewMsg;
}

//------------------------------------------------------------
// AddParam() - Adds a parameter to a Message Structure
//
//
void AddParam(struct rr_msg **RRMsg, int ParamType, void *ParamData,
				  int ParamLen)
{
	size_t MsgSize;
	unsigned short MsgLen;
	struct rr_param *CurParam;
	struct rr_msg *CurMsg;
	struct rr_msg *NewMsg;

	CurMsg = *RRMsg;

	// Get the current length of the message
	MsgLen =	ntohs(CurMsg->header.msg_len);
	// Calculate the new size of the message structure
	MsgSize = ntohs(CurMsg->header.msg_len) + ParamLen + 4;
	// Reallocate memory for the message
	NewMsg = realloc(CurMsg, MsgSize);

	NewMsg->header.msg_len = htons(MsgSize);
	
	// Construct a message parameter
	CurParam = malloc(ParamLen + 4);
	CurParam->param_type = htons(ParamType);
	CurParam->param_len = htons(ParamLen + 4);
	memcpy(CurParam->data, ParamData, ParamLen);

	// copy the parameter data to the message
	memcpy((char *)NewMsg + MsgLen, CurParam, ParamLen + 4);

	// Dispose of the parameter
	free(CurParam);

	// Return the pointer in case it changed during re-allocation
	*RRMsg =	NewMsg;

	return;
	
}

void AddShortParam(struct rr_msg **RRMsg, int ParamType,
						 unsigned short ParamData)
{
	ParamData = htons(ParamData);
	AddParam(RRMsg, ParamType,	&ParamData, 2);
}

void AddLongParam(struct rr_msg **RRMsg, int ParamType,
						 unsigned long ParamData)
{
	ParamData = htonl(ParamData);
	AddParam(RRMsg, ParamType,	&ParamData, 4);
}

//------------------------------------------------------------
// ExtractParam() - Scans the given message for the secified
//						  parameter type and returns a pointer to it
//						  if available
struct rr_param *ExtractParam(struct rr_msg *RRMsg, int ParamType)
{
	unsigned short MsgLen;
	unsigned short MsgIndex;
	struct rr_param *CurParam;

	MsgLen = ntohs(RRMsg->header.msg_len) - sizeof(struct rr_common_header);
	MsgIndex = 0;							// byte index into message

	while (MsgIndex < MsgLen) {
		CurParam = (struct rr_param *)&RRMsg->data[MsgIndex];

		if (ntohs(CurParam->param_type) > 24) {
			syslog(LOG_INFO, "Unknown parameter type %i received from server",
					CurParam->param_type);
			break;
		}

		if (ntohs(CurParam->param_type) == ParamType)
			return CurParam;

		// Prevent infinite loop during scan
		if (!ntohs(CurParam->param_len))
			break;

		MsgIndex += ntohs(CurParam->param_len);
	}
	
	return NULL;
	
}

