use strict;
use warnings;
use inc::Module::Install;

name     'WebService-Bitly';
author   'Yuki Shibazaki <shibayu36@gmail.com>';
all_from 'lib/Mojolicious/Plugin/CSRFDefender.pm';

requires 'Mojolicious';
requires 'String::Random';

test_requires 'Test::More';
test_requires 'Test::Class';
test_requires 'Mojolicious::Lite';
test_requires 'Test::Mojo';

auto_install;
WriteAll;

