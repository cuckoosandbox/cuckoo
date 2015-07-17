#!/bin/sh

DISTADDR="127.0.0.1"
. /etc/default/cuckoo

sudo service uwsgi start cuckoo-distributed
sudo service nginx start

for worker in $(curl -s "$DISTADDR:9003/api/node?mode=workers"); do
    sudo start cuckoo-distributed-instance "INSTANCE=$worker"
done
