#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

typedef struct arguments {
    int lower;
    int upper;
    int result;
} Args;

void *fact(void *args) {
    Args *input = (Args *) args;
    int upper = input->upper;
    int lower = input->lower;

    int p = 1;
    while(lower <= upper) {
        p *= lower++; 
    }
    input->result = p;
    return NULL;
}

int main(int argc, char** argv) {
    if(argc != 2) {
        printf("USAGE: %s <+int>\n", *argv);
        return 1;
    }

    pthread_t tid1,tid2;
    int n = atoi(*(++argv));

    int mid = n/2;

    Args args1 = {1, mid};
    Args args2 = {mid + 1, n};

    pthread_create(&tid1, NULL, &fact, (void *) &args1);
    pthread_create(&tid2, NULL, &fact, (void *) &args2);

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);

    printf(">>> n: %d Fact: %d\n", n, (args1.result) * (args2.result));
}
