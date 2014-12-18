#!/bin/sh
set -e

# TODO Load Virtual Machines into tmpfs, if enabled.

_about_upstart() {
    echo "Using Upstart technique.."
}

_install_configuration() {
    cat > /etc/default/cuckoo << EOF
# Configuration file for the Cuckoo Sandbox service.

# Username to run Cuckoo under, by default cuckoo.
USERNAME="cuckoo"

# Directory for Cuckoo, defaults to the "cuckoo" directory in the
# home directory of the cuckoo user.
CUCKOODIR="/home/cuckoo/cuckoo/"

# Log directory, defaults to the log/ directory in the Cuckoo setup.
LOGDIR="/home/cuckoo/cuckoo/log/"

# IP address the Cuckoo API will bind on.
APIADDR="127.0.0.1"

# IP address the Cuckoo Distributed API will bind on. Distributed API is by
# default turned *OFF*. Enable by uncommenting and setting the value.
# DISTADDR="127.0.0.1"

# IP address the Cuckoo Web Interface will bind on. The Cuckoo Web Interface
# is by default turned *OFF*. Enable by uncommenting and setting the value.
# WEBADDR="127.0.0.1"

# Start Cuckoo in verbose mode. Toggle to 1 to enable verbose mode.
VERBOSE="0"
EOF
}

_remove_configuration() {
    rm -f /etc/default/cuckoo
}

_install_upstart() {
    cat > /etc/init/cuckoo.conf << EOF
# Cuckoo daemon service.

description "cuckoo daemon"
start on runlevel [2345]
chdir /home/cuckoo/cuckoo

# Give Cuckoo time to cleanup.
kill signal SIGINT
kill timeout 600

pre-start script
    exec vmcloak-vboxnet0
    exec vmcloak-iptables
end script

script
    if [ "\$VERBOSE" -eq 0 ]; then
        ./cuckoo.py -u cuckoo
    else
        ./cuckoo.py -u cuckoo -d
    fi
end script
EOF

    cat > /etc/init/cuckoo-api.conf << EOF
# Cuckoo API server service.

env CONFFILE="/etc/default/cuckoo"
env APIADDR="127.0.0.1"
env LOGDIR="/home/cuckoo/cuckoo/log/"

description "cuckoo api server"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo

pre-start script
    [ -f "\$CONFFILE" ] && . "\$CONFFILE"
end script

exec ./utils/api.py -H "\$APIADDR" 2>> "\$LOGDIR/api.log"
EOF

    cat > /etc/init/cuckoo-process.conf << EOF
# Cuckoo results processing service.

env CONFFILE="/etc/default/cuckoo"
env LOGDIR="/home/cuckoo/cuckoo/log/"

description "cuckoo results processing"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo

pre-start script
    [ -f "\$CONFFILE" ] && . "\$CONFFILE"
end script

exec ./utils/process.py auto 2>> "\$LOGDIR/process.log"
EOF

    cat > /etc/init/cuckoo-distributed.conf << EOF
# Cuckoo distributed API service.

env CONFFILE="/etc/default/cuckoo"
env DISTADDR=""
env LOGDIR="/home/cuckoo/cuckoo/log/"

description "cuckoo distributed api service"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo

pre-start script
    [ -f "\$CONFFILE" ] && . "\$CONFFILE"
end script

script
    if [ ! -z "\$DISTADDR" ]; then
        exec ./utils/dist.py "\$DISTADDR" 2>> "\$LOGDIR/process.log"
    fi
end script
EOF

    cat > /etc/init/cuckoo-web.conf << EOF
# Cuckoo Web Interface server.

env CONFFILE="/etc/default/cuckoo"
env WEBADDR=""
env LOGDIR="/home/cuckoo/cuckoo/log/"

description "cuckoo web interface service"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo/web

pre-start script
    [ -f "\$CONFFILE" ] && . "\$CONFFILE"
end script

script
    if [ ! -z "\$WEBADDR" ]; then
        exec ./manage.py runserver "\$WEBADDR:8000" 2>&1 >> "\$LOGDIR/web.log"
    fi
end script
EOF
    echo "Cuckoo Service scripts installed!"
}

_remove_upstart() {
    rm -f /etc/init/cuckoo.conf
    rm -f /etc/init/cuckoo-api.conf
    rm -f /etc/init/cuckoo-process.conf
    rm -f /etc/init/cuckoo-distributed.conf
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

### BEGIN INIT INFO
# Provides:          cuckoo
# Required-Start:    \$remote_fs \$syslog
# Required-Stop:     \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Cuckoo Sandbox
# Description:       Cuckoo Sandbox, Automated Malware Analysis Sandbox
### END INIT INFO

PIDFILE="/var/run/cuckoo.pid"
CONFFILE="/etc/default/cuckoo"

# Default configuration values.
USERNAME="cuckoo"
CUCKOODIR="/home/cuckoo/cuckoo/"
LOGDIR="/home/cuckoo/cuckoo/log/"
APIADDR="127.0.0.1"
DISTADDR=""
WEBADDR=""

# Load configuration values.
[ -f "\$CONFFILE" ] && . "\$CONFFILE"

_start() {
    if [ -f "\$PIDFILE" ]; then
        echo "Cuckoo is already running.. please stop it first!"
        exit 1
    fi

    vmcloak-vboxnet0
    vmcloak-iptables

    echo -n "Starting Cuckoo daemon.. "
    if [ "\$VERBOSE" -eq 0 ]; then
        nohup python "\$CUCKOODIR/cuckoo.py" -u "\$USERNAME" \
            2>&1 > /dev/null &
    else
        nohup python "\$CUCKOODIR/cuckoo.py" -u "\$USERNAME" \
            -d 2>&1 > /dev/null &
    fi
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo -n "Starting Cuckoo API server.. "
    nohup python "\$CUCKOODIR/utils/api.py" -u "\$USERNAME" \
        -H "\$APIADDR" 2>&1 >> "\$LOGDIR/api.log" &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo -n "Starting Cuckoo results processing.. "
    nohup python "\$CUCKOODIR/utils/process.py" -u "\$USERNAME" \
        auto -p 2 2>&1 >> "\$LOGDIR/process.log" &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    if [ ! -z "\$DISTADDR" ]; then
        echo -n "Starting Cuckoo Distributed API.. "
        nohup python "\$CUCKOODIR/utils/dist.py" -u "\$USERNAME" \
            "\$DISTADDR" 2>&1 >> "\$LOGDIR/dist.log" &
        PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"
    fi

    if [ ! -z "\$WEBADDR" ]; then
        echo -n "Starting Cuckoo Web Interface.. "
        local pwd="$PWD"
        cd "\$CUCKOODIR/web/"
        nohup sudo -u cuckoo -i python ./manage.py runserver \
            "\$WEBADDR:8000" 2>&1 >> "\$LOGDIR/web.log" &
        PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"
        PWD="$pwd"
    fi

    echo "Cuckoo started.."
}

_stop() {
    if [ ! -f "\$PIDFILE" ]; then
        echo "Cuckoo isn't running.."
        exit 1
    fi

    echo "Stopping Cuckoo processes.."
    kill -SIGINT \$(cat "\$PIDFILE")
    echo "Cuckoo stopped.."
    rm -f "\$PIDFILE"
}

case "\$1" in
    start)
        _start \$2
        ;;

    stop)
        _stop
        ;;

    restart|force-reload)
        _stop
        _start \$2
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
    /etc/init.d/cuckoo start
}

_stop_systemv() {
    /etc/init.d/cuckoo stop
}

_restart_systemv() {
    /etc/init.d/cuckoo restart
}

case "$(lsb_release -is)" in
    Ubuntu)
        alias _about=_about_upstart
        alias _install=_install_upstart
        alias _remove=_remove_upstart
        alias _reload=_reload_upstart
        alias _start=_start_upstart
        alias _stop=_stop_upstart
        alias _restart=_restart_upstart
        ;;

    Debian)
        alias _about=_about_systemv
        alias _install=_install_systemv
        alias _remove=_remove_systemv
        alias _reload=_reload_systemv
        alias _start=_start_systemv
        alias _stop=_stop_systemv
        alias _restart=_restart_systemv
        ;;

    *)
        echo "Unsupported Linux distribution.."
        exit 1
esac

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
        _install_configuration
        _reload
        ;;

    remove)
        _remove
        _remove_configuration
        _reload
        ;;

    start)
        _start
        ;;

    stop)
        _stop
        ;;

    restart)
        _restart
        ;;

    *)
        echo "Requested invalid action."
        exit 1
esac
