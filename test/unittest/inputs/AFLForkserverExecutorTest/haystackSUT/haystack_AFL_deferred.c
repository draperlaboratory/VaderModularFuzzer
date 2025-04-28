#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

/* The unit test version of haystack_AFL_deferred create a flag file a the top of main.
   If persistent mode is working, subsequent executions will not create the flag.
*/

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

    // Create a file marking that the SUT ran. When deferred mode is working,
    // this will only happen once.
    FILE * outfile = fopen("deferred_flag", "w");
    fclose(outfile);
    
    // This call sets the fork point after the creation of the flag file
    __AFL_INIT();
    
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
    return 0;
}
