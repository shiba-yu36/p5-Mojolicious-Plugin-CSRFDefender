package t::CSRFDefender::MultipleForms;
use strict;
use warnings;

use Test::More tests => 18;

use Mojolicious::Lite;
use Test::Mojo;

# configure routing
get '/get' => 'get';
any [qw(get post)] => '/post' => 'post';

# load plugin
plugin 'Mojolicious::Plugin::CSRFDefender';

# forbidden unless session
my $t = Test::Mojo->new;
$t->post_ok('/post')->status_is(403)->content_like(qr{forbidden});

# no csrf_token if form method is get
$t->get_ok('/get')->status_is(200)->content_like(qr{(?!csrf_token)});

# set csrf_token param and session if form method is post
$t->get_ok('/post')->status_is(200)->element_exists('form[name="form1"] input[name="csrf_token"]');
$t->get_ok('/post')->status_is(200)->element_exists('form[name="form2"] input[name="csrf_token"]');
my $body = $t->tx->res->body;
my ($token_param) = $body =~ /name="csrf_token" value="(.*?)"/;
like $token_param, qr{^[a-zA-Z0-9_]+$}, 'valid token';

# forbidden unless csrf_token parameter
$t->post_ok('/post')->status_is(403)->content_like(qr{forbidden});

# can access if exists csrf_token session and parameter
$t->post_form_ok('/post' => {csrf_token => $token_param})
  ->status_is(200);

__DATA__;

@@ get.html.ep
<html>
  <body>
    <form action="/get" name="form1">
      <input name="text" />
      <input type="submit" value="send1" />
    </form>
    <form action="/get" name="form2">
      <input name="text" />
      <input type="submit" value="send2" />
    </form>
  </body>
</html>

@@ post.html.ep
<html>
  <body>
    <form action="/post" method="post" name="form1">
      <input name="text" />
      <input type="submit" value="send1" />
    </form>
    <form action="/post" method="post" name="form2">
      <input name="text" />
      <input type="submit" value="send2" />
    </form>
  </body>
</html>
