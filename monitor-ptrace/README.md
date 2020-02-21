# A ptrace based process monitor for system call interception

## Background

The ptrace version of the out-of-process monitor. Used as a comparison against the in-process monitor.


## How to use


1) The simple network server

```
./mvx_monitor ./test/epoll
```
Open another terminal:
```
$ nc localhost 5000
Hi, how are you.
```

2) Lighttpd web server

```
$ ./mvx_monitor test/lighttpd-1.4.50/src/lighttpd -f test/lighttpd.conf -D
```

Access the web server:
```
$ curl localhost:8889
<html>
<head>
... ...
```

3) Running Nginx

```
$ ./mvx_monitor ../src/elfloader/nginx.vanilla/objs/nginx
```

Test with apachenebch(ab):
```
$ ab -n 10000 -c 1 http://10.2.2.139:8000/index.html
```
