# NGINX WebDAV support of PROPFIND OPTIONS LOCK/UNLOCK
## nginx-dav-ext-module

(c) 2012 Arutyunyan Roman (arut@qip.ru, arutyunyan.roman@gmail.com)

### WARNING: This version provides experimental lock support, it's not properly tested

For full WebDAV support in NGINX you need to turn on standard NGINX 
WebDAV module (providing partial WebDAV implementation) as well as 
this module for missing methods

    ./configure --with-http_dav_module --add-module=path-to-this-module



Requirements:

	libexpat-dev


Example config:

	location / {

		dav_methods PUT DELETE MKCOL COPY MOVE LOCK UNLOCK;
		dav_ext_methods PROPFIND OPTIONS;

		root /var/root/;
	}
