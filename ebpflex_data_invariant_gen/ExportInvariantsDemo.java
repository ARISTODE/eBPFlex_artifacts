/**
 * Demonstration of how to use the exported invariant assertions
 * in actual code to ensure runtime correctness.
 */
public class ExportInvariantsDemo {
    
    // Helper to check if a number is a power of two
    private static boolean isPowerOfTwo(int n) {
        return n > 0 && (n & (n - 1)) == 0;
    }
    
    /**
     * Example implementation of ngx_palloc with assertion checking
     */
    public static int ngx_palloc(int poolSize, int requestSize) {
        // Store old values for postcondition checking
        int oldPoolSize = poolSize;
        int oldRequestSize = requestSize;
        
        // Check preconditions
        assert poolSize == 4096 || poolSize == 8192 || poolSize == 16384 : 
               "pool_size must be 4096, 8192, or 16384";
        assert isPowerOfTwo(requestSize) : "request_size must be a power of two";
        
        // Simulate the allocation logic
        int result = (requestSize <= poolSize) ? 1 : 0;
        
        // Check postconditions
        assert poolSize == oldPoolSize : "pool_size should not change";
        assert requestSize == oldRequestSize : "request_size should not change";
        assert result == 0 || result == 1 : "result must be either 0 or 1";
        
        return result;
    }
    
    /**
     * Example implementation of HTTP request processing with assertions
     */
    public static int ngx_http_process_request(int method, int uriLength) {
        // Store old values
        int oldMethod = method;
        int oldUriLength = uriLength;
        
        // Check preconditions
        assert method >= 1 : "method must be >= 1";
        
        // Simulate request processing
        int result;
        if (uriLength > 8192) {  // URI too long
            result = 414;
        } else {
            result = 200;  // OK
        }
        
        // Check postconditions
        assert method == oldMethod : "method should not change";
        assert uriLength == oldUriLength : "uri_length should not change";
        assert result == 200 || result == 414 : "result must be either 200 or 414";
        
        return result;
    }
    
    /**
     * Example of header buffer allocation with assertions
     */
    public static int ngx_http_alloc_large_header_buffer(int currentSize, int neededSize) {
        // Store old values
        int oldCurrentSize = currentSize;
        int oldNeededSize = neededSize;
        
        // Check preconditions
        assert isPowerOfTwo(currentSize) : "current_size must be a power of two";
        assert isPowerOfTwo(neededSize) : "needed_size must be a power of two";
        
        // Calculate new buffer size (next power of 2 >= neededSize)
        int result = neededSize;
        if (neededSize > currentSize) {
            result = currentSize;
            while (result < neededSize) {
                result *= 2;
            }
        }
        
        // Check postconditions
        assert currentSize == oldCurrentSize : "current_size should not change";
        assert neededSize == oldNeededSize : "needed_size should not change";
        assert isPowerOfTwo(result) : "result must be a power of two";
        
        return result;
    }
    
    public static void main(String[] args) {
        System.out.println("=== Testing Nginx Invariant Assertions ===\n");
        
        // Enable assertions with: java -ea ExportInvariantsDemo
        
        // Test 1: Valid memory allocation
        System.out.println("Test 1: Valid memory allocation");
        try {
            int result = ngx_palloc(8192, 256);
            System.out.println("✓ Success: allocated " + result);
        } catch (AssertionError e) {
            System.err.println("✗ Failed: " + e.getMessage());
        }
        
        // Test 2: Invalid pool size
        System.out.println("\nTest 2: Invalid pool size (should fail)");
        try {
            int result = ngx_palloc(5000, 256);
            System.out.println("✓ This shouldn't print");
        } catch (AssertionError e) {
            System.err.println("✗ Expected failure: " + e.getMessage());
        }
        
        // Test 3: Valid HTTP request
        System.out.println("\nTest 3: Valid HTTP request");
        try {
            int result = ngx_http_process_request(2, 1024);
            System.out.println("✓ Success: HTTP " + result);
        } catch (AssertionError e) {
            System.err.println("✗ Failed: " + e.getMessage());
        }
        
        // Test 4: Long URI
        System.out.println("\nTest 4: Long URI request");
        try {
            int result = ngx_http_process_request(1, 10000);
            System.out.println("✓ Success: HTTP " + result);
        } catch (AssertionError e) {
            System.err.println("✗ Failed: " + e.getMessage());
        }
        
        // Test 5: Header buffer allocation
        System.out.println("\nTest 5: Header buffer allocation");
        try {
            int result = ngx_http_alloc_large_header_buffer(1024, 2048);
            System.out.println("✓ Success: allocated buffer size " + result);
        } catch (AssertionError e) {
            System.err.println("✗ Failed: " + e.getMessage());
        }
        
        // Test 6: Invalid header buffer (not power of 2)
        System.out.println("\nTest 6: Invalid header buffer size (should fail)");
        try {
            int result = ngx_http_alloc_large_header_buffer(1000, 2048);
            System.out.println("✓ This shouldn't print");
        } catch (AssertionError e) {
            System.err.println("✗ Expected failure: " + e.getMessage());
        }
    }
}