/**
 * Auto-generated assertion class from Daikon invariants
 * Generated on: Mon May 26 04:02:40 UTC 2025
 */
public class GeneratedAssertions {

    // Helper methods
    private static boolean isPowerOfTwo(int n) {
        return n > 0 && (n & (n - 1)) == 0;
    }

    /**
     * Assertions for ngx_http_process_request
     */
    public static class ngx_http_process_request {

        public static void assertPreconditions(int method) {
            assert method >= 1 : "Invariant violated: method >= 1";
        }

        public static void assertPostconditions(int method, int uri_length) {
            assert method == oldmethod : "Invariant violated: method == \old(method)";
            assert uri_length == olduri_length : "Invariant violated: uri_length == \old(uri_length)";
            assert method >= 1 : "Invariant violated: method >= 1";
            assert result == 200 || result == 414 : "Invariant violated: \result == 200 || \result == 414";
        }
    }

    /**
     * Assertions for ngx_http_alloc_large_header_buffer
     */
    public static class ngx_http_alloc_large_header_buffer {

        public static void assertPreconditions(int current_size, int needed_size) {
            assert isPowerOfTwo(current_size) : "Invariant violated: daikon.tools.runtimechecker.Runtime.isPowerOfTwo(current_size)";
            assert isPowerOfTwo(needed_size) : "Invariant violated: daikon.tools.runtimechecker.Runtime.isPowerOfTwo(needed_size)";
        }

        public static void assertPostconditions(int current_size, int needed_size) {
            assert current_size == oldcurrent_size : "Invariant violated: current_size == \old(current_size)";
            assert needed_size == oldneeded_size : "Invariant violated: needed_size == \old(needed_size)";
            assert isPowerOfTwo(current_size) : "Invariant violated: daikon.tools.runtimechecker.Runtime.isPowerOfTwo(current_size)";
            assert isPowerOfTwo(needed_size) : "Invariant violated: daikon.tools.runtimechecker.Runtime.isPowerOfTwo(needed_size)";
            assert isPowerOfTwo(result) : "Invariant violated: daikon.tools.runtimechecker.Runtime.isPowerOfTwo(\result)";
        }
    }

    /**
     * Assertions for ngx_palloc
     */
    public static class ngx_palloc {

        public static void assertPreconditions(int pool_size, int request_size) {
            assert pool_size == 4096 || pool_size == 8192 || pool_size == 16384 : "Invariant violated: pool_size == 4096 || pool_size == 8192 || pool_size == 16384";
            assert isPowerOfTwo(request_size) : "Invariant violated: daikon.tools.runtimechecker.Runtime.isPowerOfTwo(request_size)";
        }

        public static void assertPostconditions(int pool_size, int request_size) {
            assert pool_size == oldpool_size : "Invariant violated: pool_size == \old(pool_size)";
            assert request_size == oldrequest_size : "Invariant violated: request_size == \old(request_size)";
            assert pool_size == 4096 || pool_size == 8192 || pool_size == 16384 : "Invariant violated: pool_size == 4096 || pool_size == 8192 || pool_size == 16384";
            assert isPowerOfTwo(request_size) : "Invariant violated: daikon.tools.runtimechecker.Runtime.isPowerOfTwo(request_size)";
            assert result == 0 || result == 1 : "Invariant violated: \result == 0 || \result == 1";
        }
    }

}
