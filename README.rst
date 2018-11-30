********************
nginx-dav-ext-module
********************

NGINX WebDAV PROPFIND and OPTIONS commands support.

.. |copy|   unicode:: U+000A9 .. COPYRIGHT SIGN

For full WebDAV support in NGINX you need to enable the standard NGINX WebDAV
module providing partial WebDAV implementation, as well as this module for the
missing methods:

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
