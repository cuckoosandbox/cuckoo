#!/bin/sh

# TODO Pre-start run vmcloak-vboxnet0.
# TODO Load Virtual Machines into tmpfs, if enabled.

_install() {
    cat > /etc/init/cuckoo.conf << EOF
# Cuckoo daemon service.

description "cuckoo daemon"
start on runlevel [2345]
setuid cuckoo
chdir /home/cuckoo/cuckoo
exec ./cuckoo.py
EOF

    cat > /etc/init/cuckoo-api.conf << EOF
# Cuckoo API server service.

description "cuckoo api server"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo
exec ./utils/api.py 2>> log/api.log
EOF

    cat > /etc/init/cuckoo-process.conf << EOF
# Cuckoo results processing service.

description "cuckoo results processing"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo
exec ./utils/process.py auto 2>> log/process.log
EOF
}

_remove() {
    rm -f /etc/init/cuckoo.conf
    rm -f /etc/init/cuckoo-api.conf
    rm -f /etc/init/cuckoo-process.conf
}

_reload() {
    initctl reload-configuration
}

_start() {
    initctl start cuckoo
}

_stop() {
    initctl stop cuckoo
}

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <install|remove|start|stop>"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "This script should be run as root."
    exit 1
fi

if [ "$1" = "install" ]; then
    _install
    _reload
elif [ "$1" = "remove" ]; then
    _remove
    _reload
elif [ "$1" = "start" ]; then
    _start
elif [ "$1" = "stop" ]; then
    _stop
else
    echo "Requested invalid action."
    exit 1
fi
