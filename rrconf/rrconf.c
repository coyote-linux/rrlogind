#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "rrconf.h"
#include "md5.h"

void cleanstr(char *str)
{
	int t;

   for (t=0; t < strlen(str); t++) {
   	if (str[t] == '\n') {
      	str[t] = '\0';
         break;
      }
	}
}

int main()
{
   struct rrconf_t rrinfo;
   char *pw1;
   char password[128];
   FILE *conffile;
   char cfname[255];

   printf("\nRoad Runner Configuration Utility %s\n\n", RRConfVersion);

   // Check for God status
   if (getuid()) {
   	fprintf(stderr, "You must be root to configure the Road Runner info.\n");
      exit(1);
   }

   // Get the necessary information from the user
   memset(&rrinfo, 0, sizeof(struct rrconf_t));
   memset(&password, 0, 21);
   printf("Road Runner Username: ");
   fgets(rrinfo.username, 20, stdin);
   cleanstr(rrinfo.username);
   if (!strlen(rrinfo.username)) {
   	fprintf(stderr, "Your username is not optional!\n");
      exit(1);
  	}
   pw1 = getpass("Road Runner Password: ");
   cleanstr(pw1);
   if (!strlen(pw1)) {
   	fprintf(stderr, "Your password is not optional!\n");
      exit(1);
  	}
   strcpy(password, pw1);
   pw1 = getpass("Confirm Password: ");
   cleanstr(pw1);
	if (strcmp(password, pw1) != 0) {
   	fprintf(stderr, "Passwords do not match.\n");
      exit(1);
   }
   cleanstr(password);
   printf("Road Runner Login Server: ");
   fgets(rrinfo.loginserver, 80, stdin);
   cleanstr(rrinfo.loginserver);
   if (!strlen(rrinfo.loginserver)) {
   	fprintf(stderr, "Your login server is not optional!\n");
      exit(1);
  	}
   // Build an MD5 Hash of the password
   md5_buffer(password, strlen(password), &rrinfo.password);
   memset(pw1, 0, strlen(pw1));
   // Open the configuration file
   strcpy(cfname, RRPath);
   strcat(cfname, RRConfFile);
   conffile = fopen(cfname, "wb");

   if (!conffile) {
   	fprintf(stderr, "\nCreation of the Road Runner configuration file failed.\n");
      fprintf(stderr, "Make sure that the %s directory exists.\n", RRPath);
      exit(1);
  	}

   if (!fwrite(&rrinfo, sizeof(struct rrconf_t), 1, conffile)) {
   	fprintf(stderr, "\nFailed to write configuration information.\n");
      fprintf(stderr, "Make sure that the disk is not full or offline.\n");
      fclose(conffile);
      exit(1);
   }

	fclose(conffile);
   printf("\nConfiguration information saved to %s.\n", cfname);

   return 0;

}
