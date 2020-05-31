public class Factorializer implements Runnable {
   private int lower, upper, answer;
   public Factorializer(int lower, int upper) {
       this.lower = lower;
       this.upper = upper;
       this.answer = 1;
   }

   public int getAnswer() {
       return answer;
   }

   public void run() {
       int lo = lower;
       int hi = upper;

       while(lo <= hi) {
           this.answer *= lo; 
           lo++;
       }
   }
}


