public class NginxSimulator {
    
    // Simulates nginx memory allocation patterns
    public static long ngx_palloc(long pool, int size) {
        if (pool == 0 || size <= 0) return 0;
        if (size > 4096) return 0; // max allocation size
        
        // Simple allocation simulation - returns pool + size as address
        return pool + size;
    }
    
    // Simulates HTTP status code validation
    public static int ngx_http_status_check(int status) {
        if (status >= 100 && status < 200) return 1; // 1xx informational
        if (status >= 200 && status < 300) return 2; // 2xx success
        if (status >= 300 && status < 400) return 3; // 3xx redirection
        if (status >= 400 && status < 500) return 4; // 4xx client error
        if (status >= 500 && status < 600) return 5; // 5xx server error
        return 0; // invalid status
    }
    
    // Simulates request method validation
    public static boolean ngx_http_method_valid(String method) {
        if (method == null) return false;
        return method.equals("GET") || method.equals("POST") || 
               method.equals("HEAD") || method.equals("PUT") || 
               method.equals("DELETE");
    }
    
    // Simulates buffer size calculations
    public static int ngx_buffer_size(int content_length, int header_size) {
        if (content_length < 0 || header_size < 0) return -1;
        int total = content_length + header_size;
        if (total > 65536) return 65536; // max buffer size
        return total;
    }
    
    public static void main(String[] args) {
        // Test memory allocation patterns
        long pool = 4096;
        int[] sizes = {16, 32, 64, 128, 256, 512, 1024, 2048};
        for (int size : sizes) {
            long addr = ngx_palloc(pool, size);
            System.out.println("Alloc size=" + size + " addr=" + addr);
        }
        
        // Test HTTP status codes
        int[] statuses = {100, 101, 200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503};
        for (int status : statuses) {
            int category = ngx_http_status_check(status);
            System.out.println("Status " + status + " category=" + category);
        }
        
        // Test request methods
        String[] methods = {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", null};
        for (String method : methods) {
            boolean valid = ngx_http_method_valid(method);
            System.out.println("Method " + method + " valid=" + valid);
        }
        
        // Test buffer calculations
        int[][] bufferTests = {{100, 50}, {1000, 100}, {10000, 500}, {50000, 1000}, {70000, 2000}};
        for (int[] test : bufferTests) {
            int bufferSize = ngx_buffer_size(test[0], test[1]);
            System.out.println("Content=" + test[0] + " Header=" + test[1] + " Buffer=" + bufferSize);
        }
    }
}