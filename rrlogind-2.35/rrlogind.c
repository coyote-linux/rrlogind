// rrlogind.c  -  Main module for rrlogind
//
// Author: Joshua Jackson		(jjackson@vortech.net)
//
#include "roadrunner.h"

int Version_ID = 12;
char OS_ID[257]="Linux";
char OS_Version[257]="2.2";

// Global Application Parameters
int DebugFlag = 0;
int VerboseFlag = 0;
int KeepAliveMonitor = 1;
int AlwaysTrust = 0;

// Global Session Parameters
char Nonce[16];
char HashedPW[16];
char UserName[21];
int SignalState = RR_STATE_IDLE;

// Local Session Parameters
int ConsoleDetach = 1;

void usage()
{
	printf("\nrrlogind  %s - Road Runner Authentication Daemon.\n\n", RRLOGIND_VERSION);
	printf("Author: Joshua Jackson   (jjackson@vortech.net)\n");
	printf("rrlogind Home Page: http://www.vortech.net/rrlinux\n\n");
	printf("Usage: rrlogind	[-p port] [-v] [-d] [-k] [-t] [-n] [-V]\n\n");
	exit(1);
}

static void sigHandler (int sig)
{
 	switch (sig) {
     case SIGTERM:
          syslog(LOG_INFO, "Caught SIGTERM.");
          SignalState = RR_STATE_LOGOUT;
          break;
     case SIGINT:
          syslog(LOG_INFO,"Caught SIGINT.");
          SignalState = RR_STATE_LOGOUT;
          break;
     case SIGHUP:
          syslog(LOG_INFO,"Caught SIGHUP, restarting.");
          SignalState = RR_STATE_LOGIN;
          break;
	}
}

void ClientLoop()
{
   int ListenSock;
   unsigned short ListenPort;
	int RequestState = RR_STATE_PROTONEG;
	int ClientState;
	int RetryCount = 0;

   // Create our listener
   ListenSock = RRListen(&ListenPort);

	if (ListenSock > 0) {

     	// Begin main client state loop -------------------------------
		do {
			// Make sure that we weren't signaled before setting
			// ClientState
 			if (SignalState == RR_STATE_IDLE)
				ClientState = RequestState;
			else {
				ClientState = SignalState;
				SignalState = RR_STATE_IDLE;
			}

			switch (ClientState) {
				case RR_STATE_PROTONEG:
					RequestState = RRProtoNeg();
					break;
         	case RR_STATE_LOGIN:
					RequestState = RRLogin(ListenPort);
					if (RequestState == RR_STATE_IDLE)
						RetryCount = 0;
					break;
         	case RR_STATE_LISTENER:
					RequestState = RRHandleRequest(ListenSock);
              	break;
				case RR_STATE_IDLE:
					RequestState = CheckRequests(ListenSock);
					break;
				case RR_STATE_LOGOUT:
					RRLogout();
					break;
				case RR_STATE_INTR:
					break;
				case RR_STATE_RETRY:
					// A non-fatal error has occured, sleep for 60 sec and recycle
					RetryCount++;
					// rrlogind will recyle for up to 1 hour and then give up
					if (RetryCount > 60) {
		         	syslog(LOG_INFO,"Retry count exceeds 60, bailing out.\n");
						RequestState = RR_STATE_ABORT;
						break;
					}
					sleep(60);
					RequestState =	RR_STATE_PROTONEG;
					break;
			}

		} while ((ClientState != RR_STATE_LOGOUT) && (ClientState != RR_STATE_ABORT));
     // End main client state loop -------------------------------
	}
   close(ListenSock);
}

void SetVersions()
{
	struct utsname name;

	if (uname(&name) != -1) {
		// attempt to get system succeeded, set the version info
		memset(OS_ID, 0, sizeof(OS_ID));
		memset(OS_Version, 0, sizeof (OS_Version));
		strncpy(OS_ID, name.sysname, 256);
		strncpy(OS_Version, name.release, 256);
	}
}

void InitParams(int argc, char **argv)
{
	struct rrconf_t rrinfo;
	FILE *conffile;
	char conffilename[255];
	struct stat buf;
	unsigned short SessionPort = 60000;

   argc--;
   argv++;

   while (argc) {
  		if (!strcmp(*argv, "-p")) {
       	argc--; argv++;
       	if (!argc) usage();
       	SessionPort = atoi(*argv);
		} else if (!strcmp(*argv, "-v")) {
			VerboseFlag = 1;
		} else if (!strcmp(*argv, "-k")) {
			KillCurProc("/var/run/rrlogind.pid");
		} else if (!strcmp(*argv, "-t")) {
			AlwaysTrust = 1;
		} else if (!strcmp(*argv, "-V")) {
			printf("rrlogind %s\n", RRLOGIND_VERSION);
			exit(0);
		} else if (!strcmp(*argv, "-n")) {
			KeepAliveMonitor = 0;
		} else if (!strcmp(*argv, "-h")) {
			usage();
		} else if (!strcmp(*argv, "-?")) {
			usage();
		} else if (!strcmp(*argv, "-d")) {
			ConsoleDetach = 0;
			DebugFlag = 1;
		} else
			break;
		argc--; argv++;
	}

	if (argc) {
		usage();
	}

	if (!stat("/var/run/rrlogind.pid", &buf)) {
		printf("PID file exists, rrlogind may already be running.\n");
		printf("If it is not running, or you wish to kill the process,\n");
		printf("use the -k parameter.\n");
		exit(1);
	}

	strcpy(conffilename, RRPath);
	strcat(conffilename, RRConfFile);

	if (!(conffile = fopen(conffilename, "r"))) {
		fprintf(stderr, "\nUnable to open Road Runner config file %s\n", conffilename);
		fprintf(stderr, "Run the rrconf configuration utility.\n");
		exit(1);
	}

	if	(!fread(&rrinfo, sizeof(struct rrconf_t), 1, conffile)) {
		printf("\nUnable to read configuration data from file.\n");
		printf("Run the rrconf configuration utility.\n");
		fclose(conffile);
		exit(1);
	}

	fclose(conffile);

	// Open the system logger
	openlog("rrlogind", LOG_PID, LOG_LOCAL0);
	syslog(LOG_INFO, "rrlogind %s started.\n", RRLOGIND_VERSION);

	// Set the configuration info
	memset(UserName, 0, sizeof(UserName));
	strncpy(UserName, rrinfo.username, 20);
	memcpy(HashedPW, rrinfo.password, 16);

	// Add the specified server to the list of session servers
	AddServer(&session_servers, rrinfo.loginserver, SessionPort);

	// If the initial session server list was not created, bail
	if (!session_servers) {
		syslog(LOG_INFO, "Null session server list, bailing out.\n");
		exit(1);
	}

	// Set the operating system version
	SetVersions();

}

int main(int argc, char **argv)
{
	// Trap Signals
   signal(SIGTERM, sigHandler);
   signal(SIGINT, sigHandler);
   signal(SIGHUP, sigHandler);
	// Process command line
 	InitParams(argc, argv);
	// Detach
	if (ConsoleDetach)
		DaemonInit("/var/run/rrlogind.pid");
	// Do that daemon kinda thang...
   ClientLoop();
	// Done... clean up the PID file.
	if (ConsoleDetach) {
		// Attempt to regain root priviledges
		seteuid(0);
		setegid(0);
		if (unlink("/var/run/rrlogind.pid") < 0 ) {
			syslog(LOG_INFO, "Error deleting PID file: %m\n");
		}
	}
   exit(0);
}

