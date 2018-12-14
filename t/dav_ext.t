#!/usr/bin/perl

# (C) Roman Arutyunyan

# Tests for nginx-dav-ext-module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use HTTP::DAV

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(13);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    dav_ext_lock_zone zone=foo:10m timeout=10s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            dav_methods PUT DELETE MKCOL COPY MOVE;
            dav_ext_methods PROPFIND OPTIONS LOCK UNLOCK;
            dav_ext_lock zone=foo;
        }
    }
}

EOF

$t->write_file('foo', 'foo');

$t->run();

###############################################################################

my $url = "http://127.0.0.1:8080";

my $content;

my $d = HTTP::DAV->new();
$d->open($url);

my $p = $d->propfind('/', 1);
is($p->is_collection, 1, 'propfind dir collection');
is($p->get_property('displayname'), '/', 'propfind dir displayname');
is($p->get_uri(), 'http://127.0.0.1:8080/', 'propfind dir uri');

$p = $d->propfind('/foo');
is($p->is_collection, 0, 'propfind file collection');
is($p->get_property('displayname'), 'foo', 'propfind file displayname');
is($p->get_uri(), 'http://127.0.0.1:8080/foo', 'propfind file uri');
is($p->get_property('getcontentlength'), '3', 'propfind file size');

my $d2 = HTTP::DAV->new();
$d2->open($url);

$d->lock('/foo');
is($d->lock('/foo'), 0, 'prevent double lock');

$d->unlock('/foo');
is($d->lock('/foo'), 1, 'relock');

$content = "bar";
$d->put(\$content, '/foo');
$content = '';
$d->get('/foo', \$content);
is($content, 'bar', 'put lock');

$content = "qux";
$d2->put(\$content, '/foo');
$content = '';
$d2->get('/foo', \$content);
isnt($content, 'qux', 'prevent put lock');

$d->mkcol('/d');
$d->lock('/d/');
$d->copy('/foo', '/d/foo');
$content = '';
$d->get('/d/foo', \$content);
is($content, 'bar', 'copy lock');

$d->unlock('/foo');
$d2->copy('/foo', '/d/bar');
$d2->get('/d/bar', \$content);
isnt($content, 'bar', 'prevent copy lock');

$d->unlock('/d');


###############################################################################
