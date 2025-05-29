#!/bin/bash

echo "Running nginx under Kvasir..."

# Create output directory
mkdir -p /home/daikon-output

# Run nginx under kvasir with selective function tracing
# We'll focus on core nginx functions
/home/kvasir --tool=fjalar \
    --dump-trace-file=/home/daikon-output/nginx.dtrace \
    --var-list-file=/home/daikon-output/nginx.vars \
    --dump-ppt-file=/home/daikon-output/nginx.decls \
    --dump-var-file=/home/daikon-output/nginx.vars.out \
    --ppt-list-file=/home/ppt-list.txt \
    /home/nginx-install/sbin/nginx -c /home/nginx-install/conf/nginx-test.conf &

KVASIR_PID=$!

# Wait for nginx to start under kvasir
sleep 5

echo "Making test requests..."
# Make simple requests
curl -s http://localhost:8080/ > /dev/null
curl -s http://localhost:8080/test > /dev/null

# Give time for processing
sleep 2

# Stop nginx gracefully
echo "Stopping nginx..."
/home/nginx-install/sbin/nginx -c /home/nginx-install/conf/nginx-test.conf -s stop

# Wait for kvasir to finish
wait $KVASIR_PID

echo "Kvasir trace generation completed"