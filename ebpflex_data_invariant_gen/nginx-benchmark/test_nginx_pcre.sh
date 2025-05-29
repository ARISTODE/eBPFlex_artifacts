#!/bin/bash

# Start nginx with PCRE-enabled config
echo "Starting nginx with PCRE configuration..."
/home/nginx-install/sbin/nginx -c /home/nginx-install/conf/nginx-pcre-test.conf &
NGINX_PID=$!

# Wait for nginx to start
sleep 2

echo "Making test requests to exercise PCRE/regex functionality..."

# Test regex location matches
curl -s http://localhost:8080/api/v1/users/123
curl -s http://localhost:8080/api/v2/users/456
curl -s http://localhost:8080/api/v3/users/789

# Test file extension matches
curl -s http://localhost:8080/image.jpg
curl -s http://localhost:8080/photo.png
curl -s http://localhost:8080/test.php
curl -s http://localhost:8080/script.PHP  # Case-insensitive test

# Test admin path (case-insensitive)
curl -s http://localhost:8080/admin
curl -s http://localhost:8080/ADMIN
curl -s http://localhost:8080/Admin/panel

# Test negative lookahead
curl -s http://localhost:8080/secure/private
curl -s http://localhost:8080/secure/public

# Test rewrite rules
curl -s http://localhost:8080/oldpath/document.pdf
curl -s http://localhost:8080/product/12345/laptop

# Invalid patterns to test error handling
curl -s http://localhost:8080/api/vX/users/abc  # Non-numeric version
curl -s http://localhost:8080/api/v1/users/     # Missing ID

echo "Stopping nginx..."
kill $NGINX_PID
wait $NGINX_PID 2>/dev/null

echo "PCRE test completed"