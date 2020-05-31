/* Test file for several function calls in sequence*/

int function_call(int param){
  if(param == 0){
    return(0);
  } else {
    return(1);
  }
}

int function_call_two(){
  return(0);
}

int function_call_three(int a, int b){
  if((a-b) == 0){
    return(0);
  } 
  return(1);
}

int main(int argc, char **argv){
  int a = 0;
  int x = function_call(a);
  int y = function_call_two();
  int z = function_call_three(x,x);
  return(x||y||z);
}


