use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'Mojolicious::Plugin::CSRFCheck',
    AUTHOR        => 'Yuki Shibazaki <shibayu36 {at} gmail.com>>',
    VERSION_FROM  => 'lib/Mojolicious/Plugin/CSRFCheck.pm',
    ABSTRACT_FROM => 'lib/Mojolicious/Plugin/CSRFCheck.pm',
    PL_FILES      => {},
    PREREQ_PM     => {
        'Test::More' => 0,
        'version'    => 0,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES    => 'Mojolicious-Plugin-CSRFCheck-*' },
);

