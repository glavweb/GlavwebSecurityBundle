#!/bin/bash
set -x
set -e

composer config minimum-stability alpha

composer require -n $PACKAGE_NAME

php bin/phpunit

../scripts/copy.sh
