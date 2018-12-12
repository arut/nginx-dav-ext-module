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

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(9);

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

my $d;
my $url;
my $p;

$url = "http://127.0.0.1:8080";

$d = HTTP::DAV->new();
$d->open($url) or die("Couldn't open $url: " .$d->message . "\n");

$p = $d->propfind('/', 1);

#printf $p->as_string();

is($p->is_collection, 1, 'propfind root collection');
is($p->get_property('displayname'), '/', 'propfind root displayname');
is($p->get_uri(), 'http://127.0.0.1:8080/', 'propfind root uri');

my $foo;

foreach my $r ($p->get_resourcelist()->get_resources()) {
    if ($r->get_uri() eq 'http://127.0.0.1:8080/foo') {
        $foo = $r;
    }
}

isnt($foo, undef, 'propfind returns file');
is($foo->is_collection, 0, 'propfind file collection');
is($foo->get_property('displayname'), 'foo', 'propfind file displayname');
is($foo->get_property('getcontentlength'), '3', 'propfind file size');

my $d2;
my $content;

$d2 = HTTP::DAV->new();
$d2->open($url) or die("Couldn't open $url: " .$d2->message . "\n");
$d->lock('/foo') or die ("Couldn't lock: " .$d->message . "\n");

$content = "bar";
$d->put(\$content, '/foo');
$d->get('/foo', \$content);

is ($content, 'bar', 'put to locked');

$content = "qux";
$d2->put(\$content, '/foo');
$d2->get('/foo', \$content);

isnt ($content, 'qux', 'put to locked by another client');

$d->unlock('/foo');


###############################################################################
