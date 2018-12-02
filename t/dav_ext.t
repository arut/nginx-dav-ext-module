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

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            dav_methods PUT DELETE MKCOL COPY MOVE;
            dav_ext_methods PROPFIND OPTIONS;
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

$d = HTTP::DAV->new();
$url = "http://127.0.0.1:8080";

$d->open( -url => $url ) or die("Couldn't open $url: " .$d->message . "\n");

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

###############################################################################
