#!/bin/sh

# TODO Pre-start run vmcloak-vboxnet0.
# TODO Load Virtual Machines into tmpfs, if enabled.

_install_upstart() {
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

_remove_upstart() {
    rm -f /etc/init/cuckoo.conf
    rm -f /etc/init/cuckoo-api.conf
    rm -f /etc/init/cuckoo-process.conf
}

_reload_upstart() {
    initctl reload-configuration
}

_start_upstart() {
    initctl start cuckoo
}

_stop_upstart() {
    initctl stop cuckoo
}

if [ "$(lsb_release -is)" = "Ubuntu" ]; then
    echo "Using Upstart.."
    _install=_install_upstart
    _remove=_remove_upstart
    _reload=_reload_upstart
    _start=_start_upstart
    _stop=_stop_upstart
else
    echo "Unsupported Linux distribution.."
    exit 1
fi

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
