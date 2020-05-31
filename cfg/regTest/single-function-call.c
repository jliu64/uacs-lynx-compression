/* Test file for single function call*/

int function_call(int param){
  if(param == 0){
    return(0);
  } else {
    return(1);
  }
}

int main(int argc, char **argv){
  int a = 0;
  int x = function_call(a);
  return(x);
}

