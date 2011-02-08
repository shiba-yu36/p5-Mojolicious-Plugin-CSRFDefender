use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Mojolicious::Plugin::CSRFCheck',
    license             => 'perl',
    dist_author         => 'Yuki Shibazaki <shibayu36 {at} gmail.com>',
    dist_version_from   => 'lib/Mojolicious/Plugin/CSRFCheck.pm',
    requires => {
        'Test::More' => 0,
        'version'    => 0,
    },
    add_to_cleanup      => [ 'Mojolicious-Plugin-CSRFCheck-*' ],
);

$builder->create_build_script();
