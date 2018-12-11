********************
nginx-dav-ext-module
********************

NGINX WebDAV PROPFIND,OPTIONS,LOCK,UNLOCK support.

.. contents::


About
=====

Standard NGINX ngx_http_dav_module_ provides partial WebDAV implementation and
only supports GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE methods.

For full WebDAV support in NGINX you need to enable the standard
ngx_http_dav_module_ as well as this module for the missing methods:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-module=/path/to/nginx-dav-ext-module

The module can be built dynamically:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-dynamic-module=/path/to/nginx-dav-ext-module

..warning:: Trying to compile NGINX with this module but without
ngx_http_dav_module_ will result in compilation error.


Locking
=======

Locking model implemented in the module is subject to the following limitations:

- Only single-token untagged ``If`` headers are currently supported::

    If: (<urn:TOKEN>)

  See `RFC4918 If Header`_ for syntax details.

- All currently held locks are kept in a list.
  Checking if an object is constrained by a lock requires O(n) operations.
  A huge number of simultaneously held locks may degrade performance.
  Thus it is not recommended to have a large lock timeout.


Directives
==========

dav_ext_methods
---------------

========== ====
*Syntax:*  ``dav_ext_methods [PROPFIND] [OPTIONS] [LOCK] [UNLOCK]``
*Context:* http, server, location
========== ====

Enables support for the specified WebDAV methods in the current scope.

dav_ext_lock_zone
-----------------

========== ====
*Syntax:*  ``dav_ext_lock_zone zone=NAME:SIZE [timeout=TIMEOUT]``
*Context:* http
========== ====

Defines a shared zone for WebDAV locks with specified NAME and SIZE.
Also, defines a lock expiration TIMEOUT.
Default lock timeout value is 1 minute.


dav_ext_lock
------------

========== ====
*Syntax:*  ``dav_ext_lock zone=NAME``
*Context:* http, server, location
========== ====

Enables WebDAV locking in the specified scope.
Locks are stored in the shared zone specified by NAME.
This zone must be defined with the ``dav_ext_lock_zone`` directive.

Note that even though this directive enables locking capabilities in the
current scope, HTTP methods LOCK and UNLOCK should also be explicitly specified
in the ``dav_ext_methods``.


Requirements
============

``libexpat-dev``


Testing
=======

The module tests require standard nginx-tests_ and Perl HTTP::DAV library.

.. code-block:: bash

    $ export PERL5LIB=/path/to/nginx-tests/lib
    $ export TEST_NGINX_BINARY=/path/to/nginx
    $ prove t


Example 1
=========

Simple lockless example::

    location / {
        root /data/www;

        dav_methods PUT DELETE MKCOL COPY MOVE;
        dav_ext_methods PROPFIND OPTIONS;
    }


Example 2
=========

WebDAV with locking::

    http {
        dav_ext_lock_zone zone=foo:10m;

        ...

        server {
            ...

            location / {
                root /data/www;

                dav_methods PUT DELETE MKCOL COPY MOVE;
                dav_ext_methods PROPFIND OPTIONS LOCK UNLOCK;
                dav_ext_lock zone=foo;
            }
        }
    }


Example 3
=========

WebDAV with locking which works with MacOS client::

    http {
        dav_ext_lock_zone zone=foo:10m;

        ...

        server {
            ...

            location / {
                root /data/www;

                # enable creating directories without trailing slash
                set $x $uri$request_method;
                if ($x ~ [^/]MKCOL$) {
                    rewrite ^(.*)$ $1/;
                }

                dav_methods PUT DELETE MKCOL COPY MOVE;
                dav_ext_methods PROPFIND OPTIONS LOCK UNLOCK;
                dav_ext_lock zone=foo;
            }
        }
    }

.. _ngx_http_dav_module: http://nginx.org/en/docs/http/ngx_http_dav_module.html
.. _nginx-tests: http://hg.nginx.org/nginx-tests
.. _`RFC4918 If Header`: https://tools.ietf.org/html/rfc4918#section-10.4
