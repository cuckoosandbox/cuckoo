#!/bin/sh
set -e

echo "### NOTICE ###" >&2
echo "This script is a work-in-progress, has not been yet documented, " >&2
echo "and may not work as expected." >&2
echo "### END OF NOTICE ###" >&2

# TODO Load Virtual Machines into tmpfs, if enabled.

_about_upstart() {
    echo "Using Upstart technique.."
}

_install_configuration() {
    if [ -f "/etc/default/cuckoo" ]; then
        # TODO Ask yes/no to force overwrite.
        echo "Not overwriting existing configuration.."
        return
    fi

    cat > /etc/default/cuckoo << EOF
# Configuration file for the Cuckoo Sandbox service(s).

# Log directory, defaults to the log/ directory in the Cuckoo setup.
LOGDIR="$LOGDIR"

# It is possible to allow the virtual machines to connect to the entire
# internet through the vmcloak-iptables script. Enable by uncommenting and
# setting the following value. Give the network interface(s) that can allow
# internet access to the virtual machines.
# VMINTERNET="eth0 wlan0"

# IP address the Cuckoo API will bind on. Cuckoo API is by default
# turned *OFF*. Enable by uncommenting and setting the value.
# APIADDR="127.0.0.1"

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
chdir "$CUCKOO"

# Give Cuckoo time to cleanup.
kill signal SIGINT
kill timeout 600

# Restart Cuckoo if it exits.
respawn

env CONFFILE="$CONFFILE"
env VMINTERNET=""

pre-start script
    . "\$CONFFILE"

    vmcloak-vboxnet0

    if [ -n "\$VMINTERNET" ]; then
        vmcloak-iptables "\$VMINTERNET"
    fi
end script

script
    . "\$CONFFILE"

    if [ "\$VERBOSE" -eq 0 ]; then
        exec ./cuckoo.py -u "$USERNAME"
    else
        exec ./cuckoo.py -u "$USERNAME" -d
    fi
end script
EOF

    cat > /etc/init/cuckoo-process.conf << EOF
# Cuckoo results processing service.

description "cuckoo results processing"
start on started cuckoo
stop on stopped cuckoo
setuid "$USERNAME"
chdir "$CUCKOO"

# Restart Cuckoo report processing if it exits unexpectedly.
respawn

env CONFFILE="$CONFFILE"
env LOGDIR="$LOGDIR"

script
    . "\$CONFFILE"

    exec ./utils/process.py auto -p 4 2>&1 >> "\$LOGDIR/process.log"
end script
EOF

    cat > /etc/init/cuckoo-api.conf << EOF
# Cuckoo API server service.

description "cuckoo api server"
start on started cuckoo
stop on stopped cuckoo
setuid "$USERNAME"
chdir "$CUCKOO"

env CONFFILE="$CONFFILE"
env LOGDIR="$LOGDIR"
env APIADDR=""

script
    . "\$CONFFILE"

    if [ -n "\$APIADDR" ]; then
        exec ./utils/api.py -H "\$APIADDR" 2>&1 >> "\$LOGDIR/api.log"
    fi
end script
EOF

    cat > /etc/init/cuckoo-distributed.conf << EOF
# Cuckoo distributed API service.

description "cuckoo distributed api service"
start on started cuckoo
stop on stopped cuckoo
setuid "$USERNAME"
chdir "$CUCKOO"

env CONFFILE="$CONFFILE"
env LOGDIR="$LOGDIR"
env DISTADDR=""

script
    . "\$CONFFILE"

    if [ -n "\$DISTADDR" ]; then
        exec ./distributed/app.py "\$DISTADDR" 2>&1 >> "\$LOGDIR/dist.log"
    fi
end script
EOF

    cat > /etc/init/cuckoo-web.conf << EOF
# Cuckoo Web Interface server.

description "cuckoo web interface service"
start on started cuckoo
stop on stopped cuckoo
setuid "$USERNAME"
chdir "$(readlink -f "$CUCKOO/web/")"

env CONFFILE="$CONFFILE"
env LOGDIR="$LOGDIR"
env WEBADDR=""

script
    . "\$CONFFILE"

    if [ -n "\$WEBADDR" ]; then
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
    rm -f /etc/init/cuckoo-web.conf
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
CONFFILE="$CONFFILE"

# Default configuration values.
USERNAME="$USERNAME"
CUCKOO="$CUCKOO"
LOGDIR="$LOGDIR"
APIADDR=""
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

    cd "\$CUCKOO"

    echo -n "Starting Cuckoo daemon.. "
    if [ "\$VERBOSE" -eq 0 ]; then
        nohup python ./cuckoo.py -u "\$USERNAME" \
            2>&1 > /dev/null &
    else
        nohup python ./cuckoo.py -u "\$USERNAME" \
            -d 2>&1 > /dev/null &
    fi
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo -n "Starting Cuckoo results processing.. "
    nohup python ./utils/process.py -u "\$USERNAME" \
        auto -p 4 2>&1 >> "\$LOGDIR/process.log" &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    if [ -n "\$APIADDR" ]; then
        echo -n "Starting Cuckoo API server.. "
        nohup python ./utils/api.py -u "\$USERNAME" \
            -H "\$APIADDR" 2>&1 >> "\$LOGDIR/api.log" &
        PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"
    fi

    if [ -n "\$DISTADDR" ]; then
        echo -n "Starting Cuckoo Distributed API.. "
        nohup python ./distributed/app.py -u "\$USERNAME" \
            "\$DISTADDR" 2>&1 >> "\$LOGDIR/dist.log" &
        PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"
    fi

    if [ -n "\$WEBADDR" ]; then
        echo -n "Starting Cuckoo Web Interface.. "
        cd web/
        nohup sudo -u cuckoo python ./manage.py runserver \
            "\$WEBADDR:8000" 2>&1 >> "\$LOGDIR/web.log" &
        PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"
        cd ..
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

USERNAME="cuckoo"
CONFFILE="/etc/default/cuckoo"
CUCKOO="/home/cuckoo/cuckoo/"
LOGDIR="/home/cuckoo/cuckoo/log/"

# Note that this way the variables have to be set before the
# actions are invoked.
while [ "$#" -ne 0 ]; do
    ACTION="$1"
    shift

    case "$ACTION" in
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

        -u|--username)
            USERNAME="$1"
            shift
            ;;

        -c|--cuckoo)
            CUCKOO="$1"
            shift
            ;;

        -l|--logdir)
            LOGDIR="$1"
            shift
            ;;

        *)
            echo "Requested invalid action."
            exit 1
    esac
done
