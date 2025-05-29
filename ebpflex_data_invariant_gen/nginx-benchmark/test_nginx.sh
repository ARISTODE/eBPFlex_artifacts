#!/bin/bash

# Start nginx
echo "Starting nginx..."
/home/nginx-install/sbin/nginx -c /home/nginx-install/conf/nginx-test.conf &
NGINX_PID=$!

# Wait for nginx to start
sleep 2

echo "Making test requests..."
# Make various requests to exercise different code paths
curl -s http://localhost:8080/ > /dev/null
curl -s http://localhost:8080/test > /dev/null
curl -s http://localhost:8080/nonexistent > /dev/null
curl -s -X POST http://localhost:8080/test -d "data=test" > /dev/null
curl -s -H "Accept-Encoding: gzip" http://localhost:8080/ > /dev/null

echo "Stopping nginx..."
kill $NGINX_PID
wait $NGINX_PID 2>/dev/null

echo "Test completed"