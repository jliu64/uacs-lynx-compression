#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {

    int n = 2;
    int count = 0;

    count++;
    if(n == 1)
        goto done;

    count++;
    if(n == 2)
        goto done;

    count++;
    if(n == 3)
        goto done;

done:
    return(0);
}
