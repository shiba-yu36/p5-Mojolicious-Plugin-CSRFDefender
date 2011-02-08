use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Mojolicious::Plugin::CSRFDefender',
    license             => 'perl',
    dist_author         => 'Yuki Shibazaki <shibayu36 {at} gmail.com>',
    dist_version_from   => 'lib/Mojolicious/Plugin/CSRFDefender.pm',
    requires => {
        'Test::More' => 0,
        'version'    => 0,
    },
    add_to_cleanup      => [ 'Mojolicious-Plugin-CSRFDefender-*' ],
);

$builder->create_build_script();
