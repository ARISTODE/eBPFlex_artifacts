#!/bin/bash

echo "Running nginx under Kvasir with PCRE tracing..."

# Create output directory
mkdir -p /home/daikon-output-pcre

# Run nginx under kvasir with PCRE function tracing
/home/kvasir --tool=fjalar \
    --dump-trace-file=/home/daikon-output-pcre/nginx_pcre.dtrace \
    --var-list-file=/home/daikon-output-pcre/nginx_pcre.vars \
    --dump-ppt-file=/home/daikon-output-pcre/nginx_pcre.decls \
    --dump-var-file=/home/daikon-output-pcre/nginx_pcre.vars.out \
    --ppt-list-file=/home/ppt-list-pcre.txt \
    /home/nginx-install/sbin/nginx -c /home/nginx-install/conf/nginx-pcre-test.conf &

KVASIR_PID=$!

# Wait for nginx to start under kvasir
sleep 5

echo "Making test requests to exercise PCRE..."
# Test regex locations
curl -s http://localhost:8080/api/v1/users/123 > /dev/null
curl -s http://localhost:8080/api/v2/users/456 > /dev/null
curl -s http://localhost:8080/image.jpg > /dev/null
curl -s http://localhost:8080/test.php > /dev/null
curl -s http://localhost:8080/admin/test > /dev/null
curl -s http://localhost:8080/secure/private > /dev/null

# Give time for processing
sleep 2

# Stop nginx gracefully
echo "Stopping nginx..."
/home/nginx-install/sbin/nginx -c /home/nginx-install/conf/nginx-pcre-test.conf -s stop

# Wait for kvasir to finish
wait $KVASIR_PID

echo "Kvasir trace generation with PCRE completed"
echo "Trace file: /home/daikon-output-pcre/nginx_pcre.dtrace"