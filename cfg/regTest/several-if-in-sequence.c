/* Test file for several if statements in sequence within main*/

int main(int argc, char **argv){
  int a = 0;
  int b = 1;
  if(a == 0){
    b = 2;
  }
  if(b == 1){
    return(1);
  }
  if(a == 1){
    return(1);
  }
  if(b == 2){
    b = 0;
  }
  return(b);
}

