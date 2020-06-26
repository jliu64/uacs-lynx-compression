#include <stdio.h>
#include <stdlib.h>

int fact(int n) {
  if (n <= 1) {
    return 1;
  }
  else {
    return n * fact(n-1);
  }
}

int main(int argc, char *argv[]) {
  int n, f;
  if (argc < 2) {
    printf("Usage: %s <number>\n", argv[0]);
  }
  else {
    n = atoi(argv[1]);
    f = fact(n);
    printf("@@@ fact(%d) = %d\n", n, f);
    return 0;
  }
}

