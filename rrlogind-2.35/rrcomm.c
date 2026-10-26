// rrcomm.c  -  Handles RR TCP/IP communications
//
// Author: Joshua Jackson		(jjackson@vortech.net)
//
#include "roadrunner.h"

// Server Lists
struct rr_server_list *session_servers;
struct rr_server_list *login_servers;
struct rr_server_list *logout_servers;
struct rr_server_list *trusted_servers;

//------------------------------------------------------------
// RRListen() - Creates a listen socket for session status and
//              restart requests
int RRListen(unsigned short *listenport)
{
	unsigned short port;
   int s;
   struct sockaddr_in saddr;

   if ((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
     	syslog(LOG_INFO, "Error creating listen socket: %m");
      return -1;
  	}

	// Bind first available port starting at 7770
   port = 7770;
   saddr.sin_family = AF_INET;
   saddr.sin_addr.s_addr = INADDR_ANY;
   do {
   	saddr.sin_port = htons(port);
      errno = 0;
      if (bind(s, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in)) < 0) {
			if (errno != EADDRINUSE) {
           syslog(LOG_INFO, "Error binding listen socket: %m");
           close(s);
           return -1;
         } else {
	   		port++;
         }
      }
	} while (errno == EADDRINUSE);

   *listenport = port;
   syslog(LOG_INFO, "Established listener on port: %i", port);
   return s;

}

//------------------------------------------------------------
// RRConnect() - Connects to the first available server in the
//					  specified list.
int RRConnect(struct rr_server_list *server)
{
	int sockfd;
	struct rr_server_list *server_ent;
   int result;

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
	// step through the list of servers until we get a connect
	for (server_ent = server; server_ent; server_ent = server_ent->next) {
	   result = connect(sockfd, (struct sockaddr *) &server_ent->serveraddr,
							  sizeof(struct sockaddr_in));
		// If we got a successful connect, return the result
	   if (!result)
	      return sockfd;
	}
	return -1;
}

//------------------------------------------------------------
// AddServer() - Adds a server entry to the specified server
//					  list structure.
void AddServer(struct rr_server_list **server_list, char *servername,
					unsigned short port)
{
	struct hostent *hp;
	struct rr_server_list *list_head, *list_ent;
	struct in_addr *addr;
	int t=0;
	
	list_head = *server_list;
	list_ent = list_head;

   if (!(hp = gethostbyname(servername))) {
		syslog(LOG_INFO, "Unknown host %s\n", servername);
		endhostent();
     	return;
  	}

	if (list_head) {
		// walk to the end of the existing server list
		for (list_ent = list_head; list_ent->next != NULL;
				list_ent = list_ent->next);
	}
	
	addr = (struct in_addr *)*hp->h_addr_list;
	while (addr) {
		if (!list_head) {
			// Create a new server list
			list_head = malloc(sizeof(struct rr_server_list));
			memset(list_head, 0, sizeof(struct rr_server_list));
			list_ent = list_head;
		} else {
			// add a new server entry
			list_ent->next = malloc(sizeof(struct rr_server_list));
			list_ent = list_ent->next;
			memset(list_ent, 0, sizeof(struct rr_server_list));
		}
		strncpy(list_ent->servername, servername, 254);
		list_ent->serveraddr.sin_family = AF_INET;
		list_ent->serveraddr.sin_addr = *addr;
		list_ent->serveraddr.sin_port = htons(port);
		t++;
		addr = (struct in_addr *)hp->h_addr_list[t];
	}
	*server_list = list_head;

	endhostent();
}

