#!/bin/bash

cp lighttpd.conf.template lighttpd.conf

sed -i 's/usrname/'$(id -un)'/g' lighttpd.conf
sed -i 's/grpname/'$(id -gn)'/g' lighttpd.conf

head -n 7 lighttpd.conf
echo

./lighttpd-1.4.50/src/lighttpd -f lighttpd.conf -m ./lighttpd-1.4.50/src/.libs -D
