public class FactThreaded {
   public static void main(String[] args) {
        if(args.length != 1) {
            System.out.println("USAGE: java FactThreaded <+int>");
        }
        int n = 0;
        try {
            n = Integer.parseInt(args[0]);
        } catch(NumberFormatException e) {
            e.printStackTrace();
        }

        int mid = n/2;

        Factorializer r1 = new Factorializer(1, mid);
        Factorializer r2 = new Factorializer(mid+1, n);

        Thread t1 = new Thread(r1);
        Thread t2 = new Thread(r2);
        t1.start();
        t2.start();
        try {
            t1.join();
            t2.join();
        } catch(InterruptedException e) {
            e.printStackTrace();
        }

        System.out.format(">>> n: %d Fact: %d%n", n, r1.getAnswer() * r2.getAnswer());

    }

}
