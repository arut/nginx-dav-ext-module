********************
nginx-dav-ext-module
********************

nginx_ WebDAV_ PROPFIND,OPTIONS,LOCK,UNLOCK support.

.. contents::


About
=====

The standard ngx_http_dav_module_ provides partial WebDAV_ implementation and
only supports GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE methods.

For full WebDAV_ support in nginx_ you need to enable the standard
ngx_http_dav_module_ as well as this module for the missing methods.


Build
=====

Building nginx_ with the module:

.. code-block:: bash

    # static module
    $ ./configure --with-http_dav_module --add-module=/path/to/nginx-dav-ext-module

    # dynamic module
    $ ./configure --with-http_dav_module --add-dynamic-module=/path/to/nginx-dav-ext-module

Trying to compile nginx_ with this module but without ngx_http_dav_module_ will
result in compilation error.


Requirements
============

- nginx_ version >= 1.13.4
- ``libxml2`` + ``libxslt``

The ``libxslt`` library is technically redundant and is only required since this
combination is supported by nginx_ for the xslt module.
Using builtin nginx mechanisms for linking against third-party libraries
brings certain compatibility benefits.
However this redundancy can be easily eliminated in the ``config`` file.


Testing
=======

The module tests require standard nginx-tests_ and Perl ``HTTP::DAV`` library.

.. code-block:: bash

    $ export PERL5LIB=/path/to/nginx-tests/lib
    $ export TEST_NGINX_BINARY=/path/to/nginx
    $ prove t


Locking
=======

- Only the exclusive write locks are supported, which is the only type of locks
  described in the WebDAV_ specification.

- All currently held locks are kept in a list.
  Checking if an object is constrained by a lock requires O(n) operations.
  A huge number of simultaneously held locks may degrade performance.
  Thus it is not recommended to have a large lock timeout which would increase
  the number of locks.


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

dav_chmod
---------

========== ====
*Syntax:*  ``dav_chmod mode``
*Default:* ``-`` (no change)
*Context:* http, server, location
========== ====

Sets the file permissions (mode) for files uploaded via WebDAV (PUT, MKCOL).
The mode can be specified in decimal or octal format (prefixed with 0).

Examples::

    dav_chmod 0640;   # rw-r----- (owner: rw, group: r, others: none)
    dav_chmod 0660;   # rw-rw---- (owner: rw, group: rw, others: none)
    dav_chmod 644;    # decimal equivalent of 0644

.. note::
   This directive does NOT require root privileges and works with normal nginx workers.

dav_chown_user
--------------

========== ====
*Syntax:*  ``dav_chown_user username``
*Default:* ``-`` (no change)
*Context:* http, server, location
========== ====

Sets the owner (user) for files uploaded via WebDAV (PUT, MKCOL).

.. warning::
   **SECURITY WARNING**: This directive requires nginx workers to run as ``root``.
   Running nginx workers as root is **NOT RECOMMENDED** for production servers exposed to the Internet.
   
   For most use cases, prefer using ``dav_chmod`` with group permissions (setgid on the directory)
   instead of changing the file owner.

dav_chown_group
---------------

========== ====
*Syntax:*  ``dav_chown_group groupname``
*Default:* ``-`` (no change)
*Context:* http, server, location
========== ====

Sets the group for files uploaded via WebDAV (PUT, MKCOL).

.. warning::
   **SECURITY WARNING**: This directive requires nginx workers to run as ``root``.
   Running nginx workers as root is **NOT RECOMMENDED** for production servers exposed to the Internet.
   
   A safer alternative: Use ``dav_chmod 0660`` and set the setgid bit on the directory::
   
       sudo chgrp desired_group /path/to/webdav/root
       sudo chmod g+s /path/to/webdav/root

dav_chown_group
------------

========== ====
*Syntax:*  ``dav_chown_group value=user``
*Context:* http, server, location
========== ====

Enables chown, requires running nginx as root (NOT RECOMENDED)

Security Considerations
=======================

Minimizing Privileges
---------------------

The principle of least privilege states that processes should run with the minimum
privileges necessary to function.

- **For dav_chmod only**: nginx workers can run as a normal unprivileged user (``www-data``, ``nginx``, ``httpd``, etc.)
- **For dav_chown_* directives**: nginx workers MUST run as ``root``, which significantly increases security risk

Recommended approach for most deployments
------------------------------------------

1. Use only ``dav_chmod`` with appropriate group permissions
2. Set the setgid bit on the WebDAV root directory: ``chmod g+s /path/to/webdav``
3. Ensure the nginx worker user and the target user share a common group
4. Use ACLs (``setfacl``) for more granular permissions if needed

Example of secure setup without chown::

    # Create shared group
    sudo groupadd webdav
    
    # Add users to group
    sudo usermod -aG webdav www-data
    sudo usermod -aG webdav youruser
    
    # Configure directory
    sudo mkdir -p /data/webdav
    sudo chgrp webdav /data/webdav
    sudo chmod 2770 /data/webdav  # setgid + rwx for group
    
    # Nginx configuration
    location / {
        dav_chmod 0660;
        # No dav_chown_user/group needed
    }

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

Example 4
=========
WebDAV with automatic permission setting (recommended)::

    location / {
        root /data/www;

        dav_methods PUT DELETE MKCOL COPY MOVE;
        dav_ext_methods PROPFIND OPTIONS;
        
        # Set permissions to rw-rw---- (660) for uploaded files
        dav_chmod 0660;
    }

This example will automatically apply ``chmod 0660`` to every file uploaded via WebDAV, making them readable and writable by the owner and group.

Example 5
=========
WebDAV with ownership change (ADVANCED - Requires nginx workers to run as root)::

    location / {
        root /data/www;

        dav_methods PUT DELETE MKCOL COPY MOVE;
        dav_ext_methods PROPFIND OPTIONS;
        
        # Change owner and group of uploaded files
        dav_chown_user www-data;
        dav_chown_group webgroup;
    }

.. warning::
   Using ``dav_chown_user`` or ``dav_chown_group`` requires nginx workers to run as ``root``, 
   which is **NOT RECOMMENDED** for production servers exposed to the Internet. 
   Consider using only ``dav_chmod`` with proper group permissions (``setgid`` on the directory) 
   as a safer alternative.
    

.. _ngx_http_dav_module: http://nginx.org/en/docs/http/ngx_http_dav_module.html
.. _nginx-tests: http://hg.nginx.org/nginx-tests
.. _nginx: http://nginx.org
.. _WebDAV: https://tools.ietf.org/html/rfc4918
.. _`RFC4918 If Header`: https://tools.ietf.org/html/rfc4918#section-10.4
