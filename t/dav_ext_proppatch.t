#!/usr/bin/perl

# Tests for nginx-dav-ext-module, PROPPATCH.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(23);

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
            dav_ext_methods PROPFIND PROPPATCH OPTIONS LOCK UNLOCK;
            dav_ext_lock zone=foo;
        }

        location /off/ {
            dav_ext_methods PROPFIND OPTIONS;
        }
    }
}

EOF

$t->write_file('foo', 'foo');
mkdir($t->testdir() . '/off');
$t->write_file('off/bar', 'bar');
$t->write_file('a &b', 'x');

$t->run();

###############################################################################

sub proppatch {
    my ($uri, $body) = @_;
    my $len = length($body);

    return http("PROPPATCH $uri HTTP/1.0" . CRLF
        . "Host: localhost" . CRLF
        . "Content-Type: text/xml" . CRLF
        . "Content-Length: $len" . CRLF . CRLF
        . $body);
}

sub count {
    my ($r, $re) = @_;
    my @m = $r =~ /$re/g;
    return scalar @m;
}

# Windows WebDAV redirector, after PUT

my $win = '<?xml version="1.0" encoding="utf-8" ?>'
    . '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:">'
    . '<D:set><D:prop>'
    . '<Z:Win32CreationTime>Sat, 21 Nov 2026 17:00:00 GMT</Z:Win32CreationTime>'
    . '<Z:Win32LastModifiedTime>Sat, 21 Nov 2026 17:00:00 GMT'
    . '</Z:Win32LastModifiedTime>'
    . '<Z:Win32FileAttributes>00000020</Z:Win32FileAttributes>'
    . '</D:prop></D:set></D:propertyupdate>';

my $r = proppatch('/foo', $win);
like($r, qr!^HTTP/1\.1 207!, 'windows 207');
is(count($r, qr!HTTP/1\.1 403 Forbidden!), 3, 'windows propstat per property');
is(count($r, qr!xmlns:P="urn:schemas-microsoft-com:"!), 3, 'windows namespace');
like($r, qr!<P:Win32FileAttributes xmlns:P=!, 'windows property name');
like($r, qr!<D:href>/foo</D:href>!, 'windows href');

# whitespace text nodes and unprefixed elements

$r = proppatch('/foo', <<'EOF');
<?xml version="1.0"?>
<D:propertyupdate xmlns:D="DAV:">
  <D:set>
    <D:prop>
      <D:displayname>x</D:displayname>
    </D:prop>
  </D:set>
  <D:remove>
    <D:prop><Q:foo xmlns:Q="urn:q"/></D:prop>
  </D:remove>
</D:propertyupdate>
EOF
like($r, qr!^HTTP/1\.1 207!, 'pretty-printed body');
is(count($r, qr!403 Forbidden!), 2, 'set and remove');

$r = proppatch('/foo', '<?xml version="1.0"?>'
    . '<propertyupdate xmlns="DAV:"><set><prop>'
    . '<displayname>x</displayname><bar xmlns=""/>'
    . '</prop></set></propertyupdate>');
like($r, qr!^HTTP/1\.1 207!, 'default namespace');
like($r, qr!<bar xmlns=""/>!, 'property without namespace');

# errors

like(proppatch('/foo', '<D:propertyupdate xmlns:D="DAV:"><D:set>'),
    qr!^HTTP/1\.1 400!, 'malformed body');
like(proppatch('/foo', '<D:propfind xmlns:D="DAV:"/>'),
    qr!^HTTP/1\.1 400!, 'wrong root element');
like(proppatch('/foo', '<propertyupdate/>'),
    qr!^HTTP/1\.1 400!, 'root element outside DAV: namespace');
like(proppatch('/foo', ''), qr!^HTTP/1\.1 400!, 'empty body');
like(proppatch('/nonexistent', $win), qr!^HTTP/1\.1 404!, 'not found');

my $many = '<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>'
    . join('', map { "<D:p$_/>" } 1 .. 300)
    . '</D:prop></D:set></D:propertyupdate>';
like(proppatch('/foo', $many), qr!^HTTP/1\.1 400!, 'too many properties');

$r = proppatch('/foo', '<?xml version="1.0"?>'
    . '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
    . '<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:a>&e;</D:a>'
    . '</D:prop></D:set></D:propertyupdate>');
unlike($r, qr!root:!, 'external entity not loaded');

# escaping, collections

$r = proppatch('/a%20&b', $win);
like($r, qr!<D:href>/a%20&amp;b</D:href>!, 'href escaped');
like(proppatch('/', $win), qr!^HTTP/1\.1 207!, 'collection');

# method switch

like(http_options('/'), qr!Allow: [^\r]*PROPPATCH!, 'options allow');
unlike(http_options('/off/'), qr!PROPPATCH!, 'options allow disabled');
like(proppatch('/off/bar', $win), qr!^HTTP/1\.1 405!, 'disabled');

# the worker survived all of the above

like(proppatch('/foo', $win), qr!^HTTP/1\.1 207!, 'still serving');

$t->stop();

unlike($t->read_file('error.log'), qr!exited on signal!, 'no worker crashes');

###############################################################################

sub http_options {
    my ($uri) = @_;
    return http("OPTIONS $uri HTTP/1.0" . CRLF
        . "Host: localhost" . CRLF . CRLF);
}

###############################################################################
