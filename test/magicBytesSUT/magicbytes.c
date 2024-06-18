#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

void check(int input)
{
    if (input == 0xDEADBEEF)
	raise(SIGSEGV);
    else
	printf("Wrong.");
}

int main(int argc, char **argv) {
    int   fd = 0;
    char  input[11];
    memset(input, 0, sizeof(input));
    int   n;
    if (argc == 2) {
        if ((fd = open(argv[1], O_RDONLY)) < 0) {
            exit(-1);
        }
        if ((n = read(fd, input, 10)) < 1) {
            return 1;
        }
    } else {
	printf("Requires 1 argument: path to input file");
        exit(-1);
    }
    
    // Convert input bytes to int
    int * x = (int *)(&input);
    int fuzz_int = *(x);
    printf("Fuzz input: %d\n", fuzz_int);
    check(fuzz_int);
    return 0;
}
