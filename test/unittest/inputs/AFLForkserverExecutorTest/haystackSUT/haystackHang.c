#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

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

    while (1) {};
}

int main(int argc, char **argv) {
    int   fd = 0;
    char  input[11];
    int   n;

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
    check_hang(input);
    return 0;
}
