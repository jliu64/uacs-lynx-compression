#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

unsigned char fib[] = {
  0x55,
  0x48, 0x89, 0xe5,
  0x53,
  0x48, 0x83, 0xec, 0x18,
  0x89, 0x7d, 0xec,
  0x83, 0x7d, 0xec, 0x00,
  0x74, 0x06,
  0x83, 0x7d, 0xec, 0x01,
  0x75, 0x07,
  0xb8, 0x01, 0x00, 0x00, 0x00,
  0xeb, 0x1e,
  0x8b, 0x45, 0xec,
  0x83, 0xe8, 0x01,
  0x89, 0xc7,
  0xe8, 0xd4, 0xff, 0xff, 0xff,
  0x89, 0xc3,
  0x8b, 0x45, 0xec,
  0x83, 0xe8, 0x02,
  0x89, 0xc7,
  0xe8, 0xc5, 0xff, 0xff, 0xff,
  0x01, 0xd8,
  0x48, 0x83, 0xc4, 0x18,
  0x5b,
  0x5d,
  0xc3 };

char* fib_addr;

int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("USAGE: fib_rec <+int>\n");
        return 1;
    }

    int n = atoi(*(++argv));
    fib_addr  = ((unsigned long)&fib & (unsigned long)(~0x7FF));
    int (*f)(int n);
    f = &fib;

    if(n < 0) {
        printf("Error: negative number\n");
        return -1;
    }

    mprotect(fib_addr, 1, PROT_EXEC|PROT_WRITE|PROT_READ);

    printf(">>> n: %d Fibonnaci: %d\n", n, (*f)(n));

    mprotect(fib_addr, 1,PROT_READ | PROT_WRITE);
}
