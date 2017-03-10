#!/bin/sh

# Install Suricata.
# $ sudo apt-get install software-properties-common
# $ sudo add-apt-repository ppa:oisf/suricata-stable
# $ sudo apt-get update
# $ sudo apt-get install suricata
#
# Setup Suricata configuration.
#
# In /etc/default/suricata, set RUN to "no".
#
# In /etc/suricata/suricata.yaml apply the following changes;
# * Set "unix-command.enabled" to "yes".
# * Set "unix-command.filename" to "cuckoo.socket".
# * Set "outputs.eve-log.enabled" to "yes".
# * Set "run-as.user to "your cuckoo user"
# * Set "run-as.group to "your cuckoo user group"
# * TODO More items.
#
# Add "@reboot /opt/cuckoo/utils/suricata.sh" to the root crontab.

. /etc/default/cuckoo

# Do we want to run Suricata in the background?
if [ "$SURICATA" -eq 0 ]; then
    exit
fi

mkdir /var/run/suricata
chown cuckoo:cuckoo /var/run/suricata

suricata --unix-socket -D

while [ ! -e /var/run/suricata/cuckoo.socket ]; do
    sleep 1
done
