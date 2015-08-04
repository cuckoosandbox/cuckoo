#!/bin/sh

DISTADDR="127.0.0.1"
. /etc/default/cuckoo

for worker in $(curl -s "$DISTADDR:9003/api/node?mode=workers"); do
    sudo stop cuckoo-distributed-instance "INSTANCE=$worker"
done

sudo stop cuckoo-distributed-instance INSTANCE=dist.status
sudo stop cuckoo-distributed-instance INSTANCE=dist.scheduler

sudo service uwsgi stop cuckoo-distributed
sudo service nginx stop
