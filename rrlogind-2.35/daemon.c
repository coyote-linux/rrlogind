// daemon.c  -  Routines for starting and killing the daemon process
//
// Author: Joshua Jackson		(jjackson@vortech.net)
//
#include "roadrunner.h"
#include "grp.h"
#include "pwd.h"

// Sets the running security context of the daemon
int SetDaemonCTX(const char *pidfile)
{
	struct group *gent;
	struct passwd *uent;

	int gid, uid;

	// By default, use the 'daemon:daemon' security context
	// Get the group id from the 'daemon' group
	gent = getgrnam("daemon");
	if (!gent) {
		syslog(LOG_INFO, "Error obtaining group information for group: daemon\n");
		gid = 0;
	} else
		gid = gent->gr_gid;
	// Get the user id of the 'daemon' user
	uent = getpwnam("daemon");
	if (!uent) {
		syslog(LOG_INFO, "Error obtaining user information for user: daemon\n");
		uid = 0;
	} else
		uid = uent->pw_uid;

	// Set the owner of the PID file
	chown(pidfile, uid, gid);	
	// Set the context
	seteuid(uid);
	setegid(gid);

	return 0;
}

void DaemonInit(const char *pidfile)
{
	char s[10];
	pid_t pid;
	int   fd;

	if ( (pid = fork() ) < 0 ) {
		syslog(LOG_INFO, "Error detaching from console (fork)");
		exit(1);
	} else if ( pid != 0 ) {
		// This is the parent... save the PID file
		if ( pidfile != NULL ) {
			if ( (fd = creat(pidfile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0 ) {
				syslog(LOG_INFO, "Error creating PID File.");
				exit(1);
			}
			sprintf(s, "%d\n", pid);
			if ( write(fd, s, strlen(s)) < 0 ) {
				syslog(LOG_INFO, "Error writing to PID File.");
			}
			close(fd);
		}
		// Close the parent
		exit(0);
	}
	setsid();
	SetDaemonCTX(pidfile);
	chdir("/");
	umask(0);
}

void KillCurProc(char *pidfile)
{
	int fd;
	int len;
	int pid;
	char pidStr[8];

	if ( (fd = open(pidfile, O_RDONLY)) < 0 ) {
		printf("Error opening PID file: %s\n", pidfile);
		exit(1);
	}
	if ( (len = read(fd, pidStr, 8)) < 0 ) {
		printf("Error reading PID file: %s\n", pidfile);
		exit(1);
	}
	pidStr[len] = '\0';
	pid = atoi(pidStr);
	if (kill(pid, SIGTERM) < 0 ) {
		if ( unlink(pidfile) < 0 ) {
			printf("Error deleting PID file.\n");
			exit(1);
		}
		printf("Error killing process: %d (rrlogind not running).\n", pid);
		exit(1);
	}
	printf("Process (pid %d) has been successfully terminated\n", pid);
	exit(0);
}


