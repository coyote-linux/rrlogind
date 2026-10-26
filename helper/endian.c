// byteorder.c
//
// autobuild helper program that attempts to determine endian byte order

#include <sys/types.h>
#include <stdio.h>

int main ()
{
	int t = 0x12345678;
	char c[4];

	memcpy(c, &t, 4);	
	
	if (c[0] == 0x12) {
		fprintf(stdout, "BIGENDIAN\n");
		return 0;
	} else {
		fprintf(stdout, "LITTLEENDIAN\n");
		return 0;
	}
}
