#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>


int check_char_n(char chr) {
    if (chr != 'n') {
        exit(1);
    }
    return 1;
}

int check_char_e(char chr) {
    if (chr != 'e') {
        exit(1);
    }
    return 1;
}

int check_char_d(char chr) {
    if (chr != 'd') {
        exit(1);
    }
    return 1;
}

int check_char_l(char chr) {
    if (chr != 'l') {
        exit(1);
    }
    return 1;
}

void check(char *buf) {
    check_char_n(buf[0]);
    check_char_e(buf[1]);
    check_char_e(buf[2]);
    check_char_d(buf[3]);
    check_char_l(buf[4]);
    check_char_e(buf[5]);
    raise(SIGSEGV);
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
    check(input);
    return 0;
}
