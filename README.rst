********************
nginx-dav-ext-module
********************

NGINX WebDAV PROPFIND and OPTIONS commands support.

.. |copy|   unicode:: U+000A9 .. COPYRIGHT SIGN

For full WebDAV support in NGINX you need to enable the standard NGINX
ngx_http_dav_module_ providing partial WebDAV implementation, as well as this
module for the missing methods:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-module=/path/to/nginx-dav-ext-module

The module can be built dynamically:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-dynamic-module=/path/to/nginx-dav-ext-module

Directives
==========

dav_ext_methods
---------------

========== ====
*Syntax:*  ``dav_ext_methods [PROPFIND] [OPTIONS]``
*Context:* http, server, location
========== ====

Enables support for the specified WebDAV methods in the current scope.


Requirements
============

``libexpat-dev``


Testing
=======

Module tests require Perl HTTP::DAV library.

.. code-block:: bash

    $ export PERL5LIB=/path/to/nginx-tests/lib
    $ export TEST_NGINX_BINARY=/path/to/nginx
    $ prove t


Example config
==============

.. code-block::

    location / {
        root /data/www;

        dav_methods PUT DELETE MKCOL COPY MOVE;
        dav_ext_methods PROPFIND OPTIONS;
    }

.. _ngx_http_dav_module: http://nginx.org/en/docs/http/ngx_http_dav_module.html
