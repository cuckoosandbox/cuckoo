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

# It is possible to allow the virtual machines to connect to the entire
# internet through the vmcloak-iptables script. Enable by uncommenting and
# setting the following value. Give the network interface(s) that can allow
# internet access to the virtual machines.
# VMINTERNET="eth0 wlan0"

# IP address and port of the Cuckoo API. Cuckoo API is by default
# turned *OFF*. Enable by uncommenting and setting the value.
# APIADDR="127.0.0.1"
# APIPORT=8090

# IP address and port of the Cuckoo Web Interface. The Cuckoo Web Interface
# is by default turned *OFF*. Enable by uncommenting and setting the value.
# WEBADDR="127.0.0.1"
# WEBPORT=8000

# Run Suricata in the background?
SURICATA="0"

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

# Upstart ignores limits found in /etc/security/limits.conf.
limit nofile 499999 999999

env CONFFILE="$CONFFILE"
env VMINTERNET=""
env CHECKVMS="/etc/default/cuckoo-setup"

pre-start script
    . "\$CONFFILE"

    vmcloak-vboxnet0

    if [ -n "\$VMINTERNET" ]; then
        vmcloak-iptables 192.168.56.1/24 "\$VMINTERNET"
    fi

    # Check up on all VMs and fix any if required.
    if [ -f "\$CHECKVMS" ]; then
        ./utils/setup.sh -S "\$CHECKVMS" -V
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

description "start cuckoo results processing"
start on started cuckoo
stop on stopped cuckoo

env PROCESSES=4

pre-start script
    echo STARTING
    for i in \$(seq 1 \$PROCESSES); do
        start cuckoo-process2 INSTANCE=process\$i
    done
end script
EOF

    cat > /etc/init/cuckoo-process2.conf << EOF
# Cuckoo results processing service.

description "cuckoo results processing"
stop on stopping cuckoo-process
setuid "$USERNAME"
chdir "$CUCKOO"
instance \$INSTANCE

# Restart Cuckoo report processing if it exits unexpectedly.
respawn

env CONFFILE="$CONFFILE"

script
    . "\$CONFFILE"

    exec ./utils/process2.py "\$INSTANCE"
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
env APIADDR=""
env APIPORT=8090

script
    . "\$CONFFILE"

    if [ -n "\$APIADDR" ]; then
        exec ./utils/api.py -H "\$APIADDR" -p "\$APIPORT"
    fi
end script
EOF

    cat > /etc/init/cuckoo-distributed-instance.conf << EOF
# Cuckoo distributed API node instance service.

description "cuckoo distributed api node instance service"
setuid "$USERNAME"
chdir "$CUCKOO/distributed"
instance \$INSTANCE
respawn

env CONFFILE="$CONFFILE"

script
    . "\$CONFFILE"

    if [ "\$VERBOSE" -eq 0 ]; then
        exec ./instance.py "\$INSTANCE"
    else
        exec ./instance.py "\$INSTANCE" -v
    fi
end script
EOF

    cat > /etc/uwsgi/apps-available/cuckoo-distributed.ini << EOF
[uwsgi]
plugins = python
chdir = $CUCKOO/distributed
file = app.py
uid = $USERNAME
gid = $USERNAME
EOF

    ln -s /etc/uwsgi/apps-available/cuckoo-distributed.ini \
        /etc/uwsgi/apps-enabled/cuckoo-distributed.ini

    cat > /etc/nginx/sites-available/cuckoo-distributed << EOF
upstream _uwsgi_cuckoo_distributed {
    server unix:/run/uwsgi/app/cuckoo-distributed/socket;
}

server {
    # If required, prepend a listening IP address.
    listen 9003;

    location / {
        client_max_body_size 100M;
        uwsgi_pass _uwsgi_cuckoo_distributed;
        include uwsgi_params;
    }
}
EOF

    ln -s /etc/nginx/sites-available/cuckoo-distributed \
        /etc/nginx/sites-enabled/cuckoo-distributed

    cat > /etc/init/cuckoo-web.conf << EOF
# Cuckoo Web Interface server.

description "cuckoo web interface service"
start on started cuckoo
stop on stopped cuckoo
setuid "$USERNAME"
chdir "$(readlink -f "$CUCKOO/web/")"

env CONFFILE="$CONFFILE"
env WEBADDR=""
env WEBPORT=8000

script
    . "\$CONFFILE"

    if [ -n "\$WEBADDR" ]; then
        exec ./manage.py runserver "\$WEBADDR:\$WEBPORT"
    fi
end script
EOF
    echo "Cuckoo Service scripts installed!"
}

_remove_upstart() {
    rm -f /etc/init/cuckoo.conf
    rm -f /etc/init/cuckoo-api.conf
    rm -f /etc/init/cuckoo-process.conf
    rm -f /etc/init/cuckoo-process2.conf
    rm -f /etc/init/cuckoo-distributed-instance.conf
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

    *)
        echo "Unsupported Linux distribution.."
        exit 1
esac

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <install|remove|start|stop>"
    echo "-u --username: Username from which to run Cuckoo."
    echo "-c --cuckoo:   Directory where Cuckoo is located."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "This script should be run as root."
    exit 1
fi

USERNAME="cuckoo"
CONFFILE="/etc/default/cuckoo"
CUCKOO="/home/cuckoo/cuckoo/"

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

        *)
            echo "Requested invalid action."
            exit 1
    esac
done
