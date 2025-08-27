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

/* The unit test version of haystack_AFL_persist writes the number
   of in-process executions to a file so that it can be inspected by the unit test.
   When persist mode is working, we will see a number greater than one.
*/
int num_execs_in_process = 0;
void log_execution()
{
    num_execs_in_process += 1;
    FILE * outfile = fopen("persist_out.txt", "w");
    fprintf(outfile, "%d", num_execs_in_process);
    fflush(outfile);
    fclose(outfile);
}


void check(char *buf)
{
    log_execution();
    
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


void check_hang(char *buf)
{
    // Check input against 'hang'
    if (buf[0] != 'h')
	return;

    if (buf[1] != 'a')
	return;

    if (buf[2] != 'n')
	return;

    if (buf[3] != 'g')
	return;

    while (1)
    {}
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
	check_hang(input);
    }
    return 0;
}
