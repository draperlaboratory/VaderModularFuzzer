#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void doUseAfterFree() {
  printf("<Tip-toes towards a box labeled BOMB>");
  int* arr = malloc(sizeof(int)*8);
  free(arr);
  int x = arr[4];
  printf("Read bogus data: 0x%x\n", x);
}
void doHang() {
  printf("<Imitates hanging by a thread>\n");
  while (1) {}
}
void doAbort() {
  printf("Abort! Abort!\n");
  abort();
}
void doExit(int x) {
  printf("<Walks away with a sign displaying 0x%x>\n", x);
  exit(x);
}
void raiseSIGSEGV() {
  printf("<Holds up sign with SIGSEGV>\n");
  raise(SIGSEGV);
}
void raiseSIGTERM() {
  printf("<Gesturing with Austrian accent> I've been SIGTERMINATED.\n");
  raise(SIGTERM);
}

void doCoverage(int steps) {
  if (steps > 10) steps = 10;

  printf("<Step> ");
  if (steps <= 1) {
    exit(1);
  }

  printf("<Step> ");
  switch (steps) {
      case 3 ... 10:
        break;
      default:
        exit(2);
  }

  printf("<Step> ");
  for (int i = 10; i >= steps; i++) 
    if (i == 3) 
      exit(3); // Hit when steps == 3

  printf("<Step> ");
  exit(4);

}

void maybeCrash() {
  srand(time(NULL));
  int r = rand() % 4;
  /* Crash 25% of the time */
  if (r == 0) {
    printf("<Slips on banana peel>");
    raiseSIGSEGV();
  }
  else /* r == 1,2,3 */
    exit(0);
}

int main(int argc, char** argv) {
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

  char *token = strtok(input, " ");
  if (strcmp("maybe", token) == 0) maybeCrash();
  if (strcmp("asan", token) == 0) doUseAfterFree();
  if (strcmp("hang", token) == 0) doHang();
  if (strcmp("abort", token) == 0) doAbort();
  if (strcmp("segv", token) == 0) raiseSIGSEGV();
  if (strcmp("term", token) == 0) raiseSIGTERM();
  if (strcmp("exit", token) == 0) {
    /* Check for optional exit code */
    char *code = strtok(NULL, " ");
    if (token) doExit(atoi(code));
    else doExit(1);
  }
  if (strcmp("coverage", token) == 0) {
    /* Check for optional exit code */
    char *steps = strtok(NULL, " ");
    if (token) doCoverage(atoi(steps));
    else doCoverage(1);
  }

  printf("<Sad Miming>\n");
}
