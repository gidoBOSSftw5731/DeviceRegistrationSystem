#!/bin/sh

dbuser=DRSUser
dbpass='BEAPROANDCHANGEME!'
dbname=DRS

# check if root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root"
    exit 1
fi

# TODO: dependencies

#add postgresql user
sudo -u postgres createuser -D -R -S $dbuser
#add postgresql user password
sudo -u postgres psql -c "alter user \"${dbuser}\" with password '$dbpass';"
#add postgresql database
sudo -u postgres createdb $dbname -O "$dbuser"