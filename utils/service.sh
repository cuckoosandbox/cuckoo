#!/bin/sh
set -e

# TODO Pre-start run vmcloak-vboxnet0.
# TODO Load Virtual Machines into tmpfs, if enabled.

_about_upstart() {
    echo "Using Upstart technique.."
}

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
    echo "Cuckoo Service scripts installed!"
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

_restart_upstart() {
    initctl restart cuckoo
}

_about_systemv() {
    echo "Using SystemV technique.."
}

_install_systemv() {
    cat > /etc/init.d/cuckoo << EOF
#!/bin/sh
# Cuckoo service.

PIDFILE="/var/run/cuckoo.pid"

start() {
    if [ -f "\$PIDFILE" ]; then
        echo "Cuckoo is already running.. please stop it first!"
        exit 1
    fi

    echo -n "Starting Cuckoo daemon.. "
    sudo -u cuckoo -i nohup \
        python /home/cuckoo/cuckoo/cuckoo.py -d 2>&1 > /dev/null &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    if [ "\$#" -eq 2 ]; then
        IPADDR="\$2"
    else
        IPADDR="127.0.0.1"
    fi

    echo -n "Starting Cuckoo API server.. "
    sudo -u cuckoo -i nohup \
        python /home/cuckoo/cuckoo/utils/api.py -H "\$IPADDR" \
        2>&1 >> /home/cuckoo/cuckoo/log/api.log &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo -n "Starting Cuckoo results processing.. "
    sudo -u cuckoo -i nohup \
        python /home/cuckoo/cuckoo/utils/process.py auto -p 2 \
        2>&1 >> /home/cuckoo/cuckoo/log/process.log &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo "Cuckoo started.."
}

stop() {
    if [ ! -f "\$PIDFILE" ]; then
        echo "Cuckoo isn't running.."
        exit 1
    fi

    echo "Stopping Cuckoo processes.."
    kill \$(cat "\$PIDFILE")
    echo "Cuckoo stopped.."
    rm -f "\$PIDFILE"
}

case "\$1" in
    start)
        start \$*
        ;;

    stop)
        stop
        ;;

    restart|force-reload)
        stop
        start \$*
        ;;

    *)
        echo "Usage: \$0 {start|stop|restart|force-reload}" >&2
        exit 1
        ;;
esac
EOF

    chmod +x /etc/init.d/cuckoo
    echo "Cuckoo Service script installed!"
}

_remove_systemv() {
    rm -f /etc/init.d/cuckoo
}

_reload_systemv() {
    : # Nothing to do here.
}

_start_systemv() {
    /etc/init.d/cuckoo start $*
}

_stop_systemv() {
    /etc/init.d/cuckoo stop
}

_restart_systemv() {
    /etc/init.d/cuckoo restart $*
}

if [ "$(lsb_release -is)" = "Ubuntu" ]; then
    alias _about=_about_upstart
    alias _install=_install_upstart
    alias _remove=_remove_upstart
    alias _reload=_reload_upstart
    alias _start=_start_upstart
    alias _stop=_stop_upstart
    alias _restart=_restart_upstart
elif [ "$(lsb_release -is)" = "Debian" ]; then
    alias _about=_about_systemv
    alias _install=_install_systemv
    alias _remove=_remove_systemv
    alias _reload=_reload_systemv
    alias _start=_start_systemv
    alias _stop=_stop_systemv
    alias _restart=_restart_systemv
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

case "$1" in
    install)
        _about
        _install
        _reload
        ;;

    remove)
        _remove
        _reload
        ;;

    start)
        _start $*
        ;;

    stop)
        _stop
        ;;

    restart)
        _restart $*
        ;;

    *)
        echo "Requested invalid action."
        exit 1
esac
