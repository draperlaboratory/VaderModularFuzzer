#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#pragma GCC optimize("O0")
#pragma clang optimize off

int main(int argc, char **argv) 
{


    int   fd = 0;
    char  input[32];
    memset(input, 0, sizeof(input));
    int   n;

    // We avoid the error checks to not pollute the cmplog
    fd = open(argv[1], O_RDONLY);
    read(fd, input, sizeof(input) - 1);

    // Read some data of different widths
    uint32_t fourBytes = (uint32_t) (*(uint32_t *) (&input[0]));
    uint64_t eightBytes = (uint64_t) (*(uint64_t *) (&input[4]));
    char * string = &input[12];
    
    //printf("Four bytes: %x\n", fourBytes);
    //printf("Eight bytes: %lx\n", eightBytes);
    //printf("String: %s\n", string);

    int fourByteTarget = 0xDEADBEEF;
    long eightByteTarget = 0xDEADBEEFDEADBEEFL;

    // Do some comparisons 
    if (fourBytes == fourByteTarget)
    {
        printf("fourBytes == 0xDEADBEEF\n");
        raise(SIGSEGV);
    }

    if (eightBytes == eightByteTarget)
    {
        printf("eightBytes == 0xDEADBEEFDEADBEEF\n");
        raise(SIGSEGV);
    }

    if (strcmp(string, "hellothere") == 0)
    {
        printf("string == 'hellothere'\n");
        raise(SIGSEGV);
    }

    // Make a loop run 12 times, the loop back edge is a comparison that will be hit repeatedly
    for (int i = 0; i < 12; i++)
    {
        printf("Iteration %d\n", i);
    }

    return 0;
}
