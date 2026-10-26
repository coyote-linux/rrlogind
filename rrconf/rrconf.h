// ----------------
// File: rrconf.h
// Author: Joshua Jackson <jjackson@vortech.net>
//
// Road Runner Configuration Declarations
//

#ifndef _RRCONF_H_
#define _RRCONF_H_ 1

#define RRPath "/etc/roadrunner/"
#define RRConfFile "rrconf.fil"
#define RRConfVersion "v1.2"

struct rrconf_t {
	char username[20];
   char password[16];
   char loginserver[80];
};

#endif
