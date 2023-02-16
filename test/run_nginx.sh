#!/bin/bash

mkdir -p ./www-root/html
mkdir -p ./www-root/webdav
mkdir -p ./www-root/webdav/temp
mkdir -p ./www-root/logs

echo "<http>
<head></head>
<body>Hello world. Running on Nginx.</body>
</http>" > www-root/html/index.html

echo "<http>
<head></head>
<body>Hello world. Nginx WebDAV.</body>
</http>" > www-root/webdav/index.html

# Copy the configuration file and update the config
cp nginx.conf.template nginx.conf

sed -i 's/usrname/'$(id -un)'/g' nginx.conf
sed -i 's/grpname/'$(id -gn)'/g' nginx.conf
sed -i 's?\/current-dir?'`pwd`'?' nginx.conf

./nginx-1.3.9/objs/nginx -g 'daemon off;' -c $PWD/nginx.conf -p ./www-root
