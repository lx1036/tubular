
tubectl bind example-test9 tcp 127.0.0.1 1241

tubectl list

go build -o main .

systemd-run -G -E HOME="$(mktemp -d)"  -p Type=notify -p NotifyAccess=all -p ExecStartPost="/usr/local/bin/tubectl register-pid \$MAINPID example-test9 tcp 127.0.0.1 1241" /root/tubular/example/demo/main

systemd-run -G -E HOME="$(mktemp -d)"  -p Type=forking -p ExecStartPost="/usr/local/bin/tubectl register-pid \$MAINPID example-test6 tcp 127.0.0.1 1238" /root/tubular/example/demo/main

journalctl -r -u run-r0a14118c4e9b41fb95ad53e59a6bb2d7.service

tubectl register-pid 146041 example-test8 tcp 127.0.0.1 1240

systemctl daemon-reload && systemctl restart nginx