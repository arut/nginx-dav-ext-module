********************
nginx-dav-ext-module
********************

NGINX WebDAV missing commands support (PROPFIND & OPTIONS)

(c) 2012-2017 Arutyunyan Roman (arutyunyan.roman@gmail.com)


For full WebDAV support in NGINX you need to enable standard NGINX 
WebDAV module (providing partial WebDAV implementation) as well as 
this module for missing methods:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-module=/path/to/this-module

The module can be built dynamically:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-dynamic-module=/path/to/this-module

Requirements
============

	``libexpat-dev``


Example config
==============

.. code-block::

	location / {

		dav_methods PUT DELETE MKCOL COPY MOVE;
		dav_ext_methods PROPFIND OPTIONS;

		root /var/root/;
	}
