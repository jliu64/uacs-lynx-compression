/* Test file for several loops in sequence within main*/

int main(int argc, char **argv){
  int a;
  int b;
  int c;
  int temp=0;
  for(a = 0; a < 10; a++){
    temp = temp-1;
  }
  for(b=9; b >=0; b--){
    temp=temp+1;
  }
  for(c=0; c < 10; c++){
    temp=temp-1;
  }
  return(0);
}

