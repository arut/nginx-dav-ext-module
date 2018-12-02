#!/usr/bin/perl

# (C) Roman Arutyunyan

# Tests for nginx dav module.

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

my $t = Test::Nginx->new()->has(qw/http dav dav_ext/)->plan(3);

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

$t->run();

###############################################################################

my $d
my $url
my $p

$d = HTTP::DAV->new();
$url = "http://127.0.0.1:8080";

$d->open( -url => $url )
    or die("Couldn't open $url: " .$d->message . "\n");

$p = $d->propfind('/', 1)

print $p;

like($p->is_collection, 1, 'propfind collection');
like($p->get_property('displayname'), '/', 'propfind collection');
like($p->get_uri(), '/', 'propfind collection');

###############################################################################
