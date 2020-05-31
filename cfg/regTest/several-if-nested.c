/* Test file for several if statements nested within main*/

int main(int argc, char **argv){
  int a = 0;
  if(a == 0){
    a = 1;
    if(a == 0){
      return(1);
    } else {
      a = 2;
      if(a == 1){
        return(1);
      } else {
        if(a == 2){
          return(0);
        }
        return(1);
      }
    }
  }
  return(1);
}

