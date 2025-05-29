===========================================================================
ngx_http_alloc_large_header_buffer:::ENTER
daikon.tools.runtimechecker.Runtime.isPowerOfTwo(current_size)
daikon.tools.runtimechecker.Runtime.isPowerOfTwo(needed_size)
===========================================================================
ngx_http_alloc_large_header_buffer:::EXIT1
current_size == \old(current_size)
needed_size == \old(needed_size)
daikon.tools.runtimechecker.Runtime.isPowerOfTwo(current_size)
daikon.tools.runtimechecker.Runtime.isPowerOfTwo(needed_size)
daikon.tools.runtimechecker.Runtime.isPowerOfTwo(\result)
===========================================================================
ngx_http_process_request:::ENTER
method >= 1
===========================================================================
ngx_http_process_request:::EXIT1
method == \old(method)
uri_length == \old(uri_length)
method >= 1
\result == 200 || \result == 414
===========================================================================
ngx_palloc:::ENTER
pool_size == 4096 || pool_size == 8192 || pool_size == 16384
daikon.tools.runtimechecker.Runtime.isPowerOfTwo(request_size)
===========================================================================
ngx_palloc:::EXIT1
pool_size == \old(pool_size)
request_size == \old(request_size)
pool_size == 4096 || pool_size == 8192 || pool_size == 16384
daikon.tools.runtimechecker.Runtime.isPowerOfTwo(request_size)
\result == 0 || \result == 1
