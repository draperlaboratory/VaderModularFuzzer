#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

// For persistent mode, optimizations have to be turned off or some
// of the checks get optimized away.
#pragma GCC optimize("O0")
#pragma clang optimize off

void check(char *buf)
{
    // Check input against 'needle'
    if (buf[0] != 'n')
	return;

    if (buf[1] != 'e')
	return;

    if (buf[2] != 'e')
	return;

    if (buf[3] != 'd')
	return;

    if (buf[4] != 'l')
	return;

    if (buf[5] != 'e')
	return;

    raise(SIGSEGV);
}


int main(int argc, char **argv) {

    int   fd = 0;
    char  input[11];
    int   n;

    while (__AFL_LOOP(10000))
    {
	if (argc == 2) {
	    if ((fd = open(argv[1], O_RDONLY)) < 0) {
		exit(-1);
	    }
	    if ((n = read(fd, input, 10)) < 1) {
		return 1;
	    }
	} else {
	    n = read(STDIN_FILENO, input, 10);
	}
	input[n] = '\0';
	check(input);
    }
    return 0;
}
