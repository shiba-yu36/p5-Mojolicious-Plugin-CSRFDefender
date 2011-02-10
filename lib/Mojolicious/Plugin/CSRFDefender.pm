package Mojolicious::Plugin::CSRFDefender;

use strict;
use warnings;
use Carp;

use version; our $VERSION = qv('0.0.1');

use base qw(Mojolicious::Plugin);

use String::Random;

sub register {
    my ($self, $app, $conf) = @_;

    # input check
    $app->hook(after_static_dispatch => sub {
        my ($c) = @_;
        unless ($self->validate_csrf($c)) {
            $c->render(status => '403', text => 'forbidden');
        };
    });

    # output filter
    $app->hook(after_dispatch => sub {
        my ($c) = @_;
        my $token = $self->get_csrf_token($c);
        my $body = $c->res->body;
        $body =~ s{(<form\s*.*method="POST".*?>)}{$1\n<input type="hidden" name="csrf_token" value="$token" />}isg;
        $c->res->body($body);
    });

    return $self;
}

sub validate_csrf {
    my ($self, $c) = @_;

    if ($c->req->method eq 'POST') {
        my $request_token = $c->req->param('csrf_token');
        my $session_token = $c->session('csrf_token');
        return 0 unless $request_token;
        return 0 unless $session_token;
        return 0 unless $request_token eq $session_token;
    }

    return 1;
}

sub get_csrf_token {
    my ($self, $c) = @_;

    my $token = $c->session('csrf_token');
    return $token if $token;

    $token = String::Random::random_regex('[a-zA-Z0-9_]{32}');
    $c->session('csrf_token' => $token);
    return $token;
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::CSRFDefender - Defend CSRF automatically in Mojolicious Application


=head1 VERSION

This document describes Mojolicious::Plugin::CSRFDefender version 0.0.1


=head1 SYNOPSIS

    # Mojolicious
    $self->plugin('Mojolicious::Plugin::CSRFDefender');

    # Mojolicious::Lite
    plugin 'Mojolicious::Plugin::CSRFDefender';

=head1 DESCRIPTION

This plugin defends CSRF automatically in Mojolicious Application.
Following is the strategy.

=head2 output filter

When the application response body contains form tags with method="post",
this inserts hidden input tag that contains token string into forms in the response body.
For example, the application response body is

    <html>
      <body>
        <form method="post" action="/get">
          <input name="text" />
          <input type="submit" value="send" />
        </form>
      </body>
    </html>

this becomes

    <html>
      <body>
        <form method="post" action="/get">
        <input type="hidden" name="csrf_token" value="zxjkzX9RnCYwlloVtOVGCfbwjrwWZgWr" />
          <input name="text" />
          <input type="submit" value="send" />
        </form>
      </body>
    </html>

=head2 input check

For every POST requests, this module checks input parameters contain the collect token parameter. If not found, throws 403 Forbidden.

=head1 METHODS

L<Mojolicious::Plugin::CSRFDefender> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

    $plugin->register;

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

=over 4

=item * L<Mojolicious>

=back

=head1 REPOSITORY

https://github.com/shiba-yu36/p5-Mojolicious-Plugin-CSRFDefender

=head1 AUTHOR

  C<< <shibayu36 {at} gmail.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2011, Yuki Shibazaki C<< <shibayu36 {at} gmail.com> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.
