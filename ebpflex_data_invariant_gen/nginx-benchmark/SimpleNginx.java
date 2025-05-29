public class SimpleNginx {
    
    // Simple memory allocation check
    public static int checkAlloc(int size) {
        if (size <= 0) return -1;
        if (size > 4096) return -1;
        return size;
    }
    
    // Simple status code check
    public static int checkStatus(int status) {
        if (status < 100 || status >= 600) return -1;
        return status / 100; // returns 1,2,3,4,5 for status categories
    }
    
    public static void main(String[] args) {
        // Test allocations
        for (int i = 0; i <= 10; i++) {
            int size = i * 512;
            int result = checkAlloc(size);
            System.out.println("checkAlloc(" + size + ") = " + result);
        }
        
        // Test status codes
        int[] codes = {100, 200, 301, 404, 500};
        for (int code : codes) {
            int result = checkStatus(code);
            System.out.println("checkStatus(" + code + ") = " + result);
        }
    }
}