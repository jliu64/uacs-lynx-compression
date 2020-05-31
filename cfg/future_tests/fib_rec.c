#include <stdio.h>
#include <stdlib.h>

int fib(int n) {
    if(n == 0 || n == 1) { return 1; }
    return fib(n-1) + fib(n-2);
}

int main(int argc, char** argv) {
    if(argc != 2) {
        printf("USAGE: %s <+int>\n", *argv);
        return 1;
    }

    int n = atoi(*(++argv));

    if(n < 0) {
        printf("Error: negative number\n");
        return -1;
    }

    printf(">>> n: %d Fibonnaci: %d\n", n, fib(n));
}
