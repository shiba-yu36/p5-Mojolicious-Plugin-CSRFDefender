use strict;
use warnings;
use inc::Module::Install;

name     'WebService-Bitly';
author   'Yuki Shibazaki <shibayu36@gmail.com>';
all_from 'lib/Mojolicious/Plugin/CSRFDefender.pm';

requires 'Mojolicious';

auto_install;
WriteAll;

