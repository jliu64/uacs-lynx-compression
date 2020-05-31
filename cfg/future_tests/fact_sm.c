#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

unsigned char mul[] = {
  0x56,
  0x49, 0x8a, 0xe6,        
  0x8a, 0x7e, 0xfd,        
  0x8a, 0x76, 0xf9,        
  0x8c, 0x46, 0xfd,        
  0x10, 0xb0, 0x46, 0xf9,     
  0x5e,              
  0xc4};

char *mul_addr;
  
void change(int n, int delta) {
  int i;
  unsigned char ch;
  
  for (i = 0; i < n; i++) {
    ch = mul[i];
    mul[i] += delta;
  }
}

__attribute__ ((noinline)) int fact(int n) {
  int p;
  int (*f)(int p, int n);

  f = &mul;

  p = 1;
  while (n > 0) {
    p = (*f)(p,n);
    n -= 1;
  }
  
  return p;
}

int main(int argc, char **argv) {
  int n;

  mul_addr  = ((unsigned long)&mul & (unsigned long)(~0x7FF));
  //commenting this out breaks it.
//  printf("xd");
// printf("mul_addr = 0x%lx (raw), 0x%lx (page_aligned)\n",
//	 (long)(&mul), (long)(mul_addr));
  
  if (argc < 2) {
    fprintf(stderr, "Usage: %s num\n", *argv);
    exit(1);
  }
  
  n = atoi(*++argv);

  change(19, -1);
    
//  mprotect(mul_addr, 1, PROT_EXEC|PROT_READ|PROT_WRITE);
//  mprotect(mul_addr,1,PROT_NONE);
  mprotect(mul_addr, 1, PROT_EXEC|PROT_WRITE|PROT_READ);

  printf(">>> n = %d, fact = %d\n", n, fact(n));

  mprotect(mul_addr, 1,PROT_READ | PROT_WRITE);
  
  return 0;
}
