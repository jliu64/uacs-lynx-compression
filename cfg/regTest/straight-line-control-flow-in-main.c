/* Test file for straight line control flow within main*/

int main(int argc, char **argv){
  int a = 0;
  int b = a+10;
  float x = 0*(b/(b+a));
  return(x);
}
