





nginx_pid=`cat /run/nginx.pid`
echo ${nginx_pid}
/usr/local/bin/tubectl register-pid ${nginx_pid} example-test10 tcp 127.0.0.1 8080
