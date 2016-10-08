==============================
Monitoring Cuckoo with Icinga2
==============================

The following instructions assume that you have both your Cuckoo instance(s)
as well as the Icinga2 instance (which, preferably, runs on a separate server)
running on a Debian/Ubuntu-based distribution.

Note that all commands mentioned in this document should be ran as **root**
and that any highlighted lines feature some sort of user-specific
configuration.

Installing the Icinga2 master
=============================

In this chapter we'll install the ``master``, also known as the node in which
the results from the various clients / satellites may be monitored.

First add the apt key for Icinga2 on Ubuntu::

    $ wget -O - http://packages.icinga.org/icinga.key | apt-key add -
    $ echo 'deb http://packages.icinga.org/ubuntu icinga-trusty main' > /etc/apt/sources.list.d/icinga.list
    $ apt-get update

Or on Debian::

    $ wget -O - http://packages.icinga.org/icinga.key | apt-key add -
    $ echo 'deb http://packages.icinga.org/debian icinga-jessie main' > /etc/apt/sources.list.d/icinga.list
    $ apt-get update

Then we install the actual packages::

    $ apt-get install icinga2 php5-json php5-gd php5-imagick php5-mysql
    $ apt-get install php5-pgsql php5-intl php5-cli php5-common php5-fpm
    $ echo 'date.timezone = "Europe/Amsterdam"' >> /etc/php5/fpm/php.ini
    $ icinga2 feature enable command
    $ service icinga2 restart

Setup the PostgreSQL database:

.. code-block:: text
    :emphasize-lines: 2

    $ sudo -u postgres psql
    postgres=# CREATE USER icingaweb WITH PASSWORD 'YOURDATABASEPASSWORD';
    postgres=# CREATE DATABASE icingaweb;

Create a file, ``/etc/icinga2/features-enabled/ido-pgsql.conf``, with the
following contents. Use the Icinga2 database password you specified earlier:

.. code-block:: text
    :emphasize-lines: 5

    library "db_ido_pgsql"

    object IdoPgsqlConnection "ido-pgsql" {
        user = "icinga2",
        password = "YOURDATABASEPASSWORD",
        host = "localhost",
        database = "icinga2"
    }

Install the Icinga2 PostgreSQL configuration::

    $ apt-get install icinga2-ido-pgsql
    # splash screen - "configure now"
    # Yes, fill in password

    $ icinga2 feature enable ido-pgsql
    $ service icinga2 restart

Install ``icingaweb2``::

    $ apt-get install icingaweb2

    # If it installs apache2, remove it, as we'll be using nginx.
    $ apt-get remove apache2 --purge

Create the following ``nginx`` configuration at
``/etc/nginx/sites-available/icinga2``, adjust where needed:

.. code-block:: text
    :emphasize-lines: 2,4

    server {
        listen 0.0.0.0:80;

        server_name icinga2.yourdomain.tld;

        location ~ ^/index\.php(.*)$ {
            fastcgi_pass unix:/var/run/php5-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME /usr/share/icingaweb2/public/index.php;
            fastcgi_param ICINGAWEB_CONFIGDIR /etc/icingaweb2;
        }

        location ~ ^/(.*)? {
            allow all;

            alias /usr/share/icingaweb2/public;
            index index.php;

            rewrite ^/$ /dashboard;
            try_files $1 $uri $uri/ /index.php$is_args$args;
        }
    }

Make a symbolic link to the ``sites-enabled`` directory::

    $ ln -s /etc/nginx/sites-available/icinga2 /etc/nginx/sites-enabled/icinga2
    $ service nginx reload

The ``icingaweb2`` service is now accessible through http://<ip>:<port>. Setup
the web interface through the website. To start the setup, a one-time token is
required for authentication, create it as follows::

    icingacli setup token create

As for the setup itself, take the following steps.

- Step 'modules', click Next
- Step 'icinga web 2', should be all green
- Step 'Authentication', click Next
- Step 'Database Resource', fill in PostgreSQL details
- step 'Authentication Backend', click Next
- step 'Administration', create an admin account
- Next on all steps

After this is finished, login to the icinga2 web interface and notice that
icinga2 is already logging the current machine.

Configuring the Icinga2 master
==============================

As this is the master node, we will have to configure it as such. We'll use
the wizard. Start as follows:

.. code-block:: text
    :emphasize-lines: 8,9,13,14

    $ icinga2 node wizard
    Welcome to the Icinga 2 Setup Wizard!

    We'll guide you through all required configuration details.

    Please specify if this is a satellite setup ('n' installs a master setup) [Y/n]: n
    Starting the Master setup routine...
    Please specifiy the common name (CN) [cuckoocinga2]:
    Checking for existing certificates for common name 'cuckoocinga2'...
    Certificates not yet generated. Running 'api setup' now.
    [...]
    Please specify the API bind host/port (optional):
    Bind Host []: <YOUR IP ADDRESS>
    Bind Port []: <YOUR PORT>
    information/cli: Created backup file '/etc/icinga2/features-available/api.conf.orig'.
    information/cli: Updating constants.conf.
    information/cli: Created backup file '/etc/icinga2/constants.conf.orig'.
    information/cli: Updating constants file '/etc/icinga2/constants.conf'.
    information/cli: Updating constants file '/etc/icinga2/constants.conf'.
    information/cli: Updating constants file '/etc/icinga2/constants.conf'.
    Done.

    Now restart your Icinga 2 daemon to finish the installation!

    $ service icinga2 restart

The setup wizard will do the following:

- Generate a local CA in /var/lib/icinga2/ca (or use existing one)
- Generate a new CSR, sign it with the local CA and copying it into /etc/icinga2/pki
- Generate a local zone and endpoint configuration for this master based on FQDN
- Enabling the API feature, and setting optional bind_host and bind_port
- Setting the NodeName and TicketSalt constants in constants.conf

Create or modify the ``/etc/icinga2/zones.conf`` file and populate it with the
following configuration (please customize as needed):

.. code-block:: text
    :emphasize-lines: 1,4,6

    object Endpoint "icinga2.yourdomain.tld" {
    }

    object Zone "icinga2.yourdomain.tld" {
        // This is the local master zone = "master"
        endpoints = [ "icinga2.yourdomain.tld" ]
    }

Finally restart Icinga2 once again to make sure all settings are applied::

    service icinga2 restart

Notifications Events
====================

We're almost done on the master. We're going to configure Icinga2 to call our
custom script, ``/etc/icinga2/scripts/notify.py`` whenever the services
``ping4``, ``ssh``, and ``check_cuckoo`` fail. It is up to the user of Cuckoo
to implement the actual ``notify.py`` script though, as this is out of scope
for this documentation.

First of all, on master, append the following lines to
``/etc/icinga2/conf.d/users.conf``:

.. code-block:: text
    :emphasize-lines: 6

    object User "sysadmin" {
        display_name = "System Administrator"
        enable_notifications = true
        states = [ Warning, Critical ]
        types = [ Problem, Recovery ]
        email = "YOUREMAILADDRESS@YOURDOMAIN.TLD"
    }

    template Notification "generic-notification" {
        states = [ Warning, Critical, Unknown ]
        types = [ Problem, Acknowledgement, Recovery, Custom, FlappingStart,
                  FlappingEnd, DowntimeStart, DowntimeEnd, DowntimeRemoved ]
    }

    apply Notification "notify-sysadmin" to Service {
        import "generic-notification"

        command = "notify-cuckoo"
        users = [ "sysadmin" ]

        assign where service.name in ["check_cuckoo", "ssh", "ping4"]
    }

    object NotificationCommand "notify-cuckoo" {
        import "plugin-notification-command"
        command = [
            SysconfDir + "/icinga2/scripts/notify.py"
        ]

        env = {
            NOTIFICATIONTYPE = "$notification.type$"
            SERVICEDESC = "$service.name$"
            HOSTALIAS = "$host.display_name$"
            HOSTADDRESS = "$address$"
            SERVICESTATE = "$service.state$"
            LONGDATETIME = "$icinga.long_date_time$"
            SERVICEOUTPUT = "$service.output$"
            NOTIFICATIONAUTHORNAME = "$notification.author$"
            NOTIFICATIONCOMMENT = "$notification.comment$"
            HOSTDISPLAYNAME = "$host.display_name$"
            SERVICEDISPLAYNAME = "$service.display_name$"
            USEREMAIL = "$user.email$"
        }
    }

Then create the file ``/etc/icinga2/scripts/notify.py`` and have some
meaningful code in there. It'll be called every time a service fails or
recovers (you may want to use the ENV vars). Don't forget to make it
executable::

    $ chmod +x /etc/icinga2/scripts/notify.py

Configuring a Icinga2 satellite (client)
========================================

A satellite Icinga2 node connects to the master Icinga2 node using SSL. To get
started, install Icinga2 on the satellite node, i.e., a Cuckoo node.

First add the apt key for Icinga2 on Ubuntu::

    $ wget -O - http://packages.icinga.org/icinga.key | apt-key add -
    $ echo 'deb http://packages.icinga.org/ubuntu icinga-trusty main' > /etc/apt/sources.list.d/icinga.list
    $ apt-get update

Or on Debian::

    $ wget -O - http://packages.icinga.org/icinga.key | apt-key add -
    $ echo 'deb http://packages.icinga.org/debian icinga-jessie main' > /etc/apt/sources.list.d/icinga.list
    $ apt-get update

Then install Icinga2 itself::

    $ apt-get install icinga2
    $ icinga2 feature enable command
    $ service icinga2 restart

To have this satellite connect to master, we once again use the wizard to
properly configure it::

    $ icinga2 node wizard
    - Satellite setup? [Y/n]: y
    - For the common name, use the master common name you supplied earlier doing the wizard for master.
    - Establish a connection to master? [Y/n]: y
    - Fill in connection details to master
    - Leave CSR signing connection details blank
    - Please specify the request ticket: run the *hint* cmd on master to acquire the ticket and use it
    - Leave API blank
    - Accept config from master? [y/N]: y
    - Accept commands from master? [y/N]: y

As an example wizard session:

.. code-block:: text
    :emphasize-lines: 7,9,12,13,22

    $ icinga2 node wizard
    Welcome to the Icinga 2 Setup Wizard!

    We'll guide you through all required configuration details.

    Please specify if this is a satellite setup ('n' installs a master setup) [Y/n]: y
    Please specifiy the common name (CN) [cuckoo1]:
    Please specify the master endpoint(s) this node should connect to:
    Master Common Name (CN from your master setup): icinga2.yourdomain.tld
    Do you want to establish a connection to the master from this node? [Y/n]: y
    Please fill out the master connection information:
    Master endpoint host (Your master's IP address or FQDN): <YOUR IP ADDRESS>
    Master endpoint port [5665]: <YOUR PORT NUMBER>
    Add more master endpoints? [y/N]: n
    Please specify the master connection for CSR auto-signing (defaults to master endpoint host):
    Host [...]:
    Port [...]:
    [...]
    Is this information correct? [y/N]: y
    [...]
    Please specify the request ticket generated on your Icinga 2 master.
    (Hint: # icinga2 pki ticket --cn 'cuckoo1'): [...]
    [...]
    Please specify the API bind host/port (optional):
    Bind Host []:
    Bind Port []:
    Accept config from master? [y/N]: y
    Accept commands from master? [y/N]: y
    [...]
    Now restart your Icinga 2 daemon to finish the installation!

    $ service icinga2 restart

To have master notice the newly added satellite, run the following commands on
the server where the Icinga2 master is running::

    $ icinga2 node update-config
    $ service icinga2 restart

    # Optionally you may verify the current configuration.
    $ icinga2 object list --type Host

The newly added satellite should show up in the list.

Setting up the Cuckoo check service
===================================

We'll make a custom service that checks if Cuckoo is currently working on the
satellite. This code will run locally on each satellite node.

On the satellite create the following file
``/usr/lib/nagios/plugins/check_cuckoo`` with the following contents.

.. code-block:: python

    #!/usr/bin/python
    import sys
    import argparse
    import requests
    from math import log

    if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("-H", "--host", help="API server host",
                            default="localhost", action="store", required=True)
        parser.add_argument("-p", "--port", help="API server port",
                            default=8090, action="store", required=True)
        args = parser.parse_args()

    def pretty_size(n, pow=0, b=1024, u='B', pre=[''] + [p + 'i' for p in 'KMGTPEZY']):
        pow, n = min(int(log(max(n * b ** pow, 1), b)), len(pre) - 1), n * b ** pow
        return "%%.%if %%s%%s" % abs(pow % (-pow - 1)) % (n / b ** float(pow), pre[pow], u)

    def json_to_nagios(blob, base=""):
        def _format(key, val):
            if "diskspace" in key and isinstance(val, (int, float)):
                size = pretty_size(val, b=1024, u='B', pre=['', 'K', 'M', 'G'])
                return "%s=%s " % (key, size.replace(" ", ""))
            elif isinstance(val, (int, float)):
                return "%s=%s " % (key, str(val))
            else:
                # returning strings in nagios labels not allowed
                return ""

        rtn = ""
        if isinstance(blob, dict):
            for _k, _v in blob.iteritems():
                key = base + "_" + _k
                if isinstance(_v, dict):
                    rtn += json_to_nagios(_v, key)
                else:
                    rtn += _format(key, _v)
        elif isinstance(blob, list):
            #rtn += "%s=(%s) " % (base, ",".join([str(z) for z in blob]))
            pass
        else:
            rtn += _format(base, str(blob))

        return rtn

    url = "http://%s:%s/cuckoo/status" % (args.host, args.port)

    try:
        resp = requests.get(url, timeout=5)
        if not resp.status_code == 200:
            raise Exception("status code not 200")

        resp = resp.json()
    except Exception as ex:
        print "Error - %s" % str(ex)
        sys.exit(2)

    output = "Cuckoo %s OK|" % resp["version"]

    for k, v in resp.iteritems():
        output += json_to_nagios(v, base=k)

    print output
    sys.exit(0)

Don't forget to make it executable::

    $ chmod +x /usr/lib/nagios/plugins/check_cuckoo

Now open ``/etc/icinga2/conf.d/services.conf``, remove everything, and paste
the following lines::

    apply Service "ping4" {
        import "generic-service"
        check_command = "ping4"
        assign where host.address
    }

    apply Service "ssh" {
        import "generic-service"
        check_command = "ssh"
        assign where (host.address || host.address6) && host.vars.os == "Linux"
    }

    apply Service for (disk => config in host.vars.disks) {
        import "generic-service"
        check_command = "disk"
        vars += config
    }

    apply Service "icinga" {
        import "generic-service"
        check_command = "icinga"
        assign where host.name == NodeName
    }

    apply Service "load" {
        import "generic-service"
        check_command = "load"
        /* Used by the ScheduledDowntime apply rule in `downtimes.conf`. */
        vars.backup_downtime = "02:00-03:00"
        assign where host.name == NodeName
    }

    apply Service "swap" {
        import "generic-service"
        check_command = "swap"
        assign where host.name == NodeName
    }

    apply Service "check_cuckoo" {
        import "generic-service"
        check_command = "check_cuckoo"
        assign where host.name == NodeName
    }

Then append the following lines to ``/etc/icinga2/conf.d/commands.conf``::

    object CheckCommand "check_cuckoo" {
        import "plugin-check-command"

        command = [ PluginDir + "/check_cuckoo" ]

        arguments = {
            "-H" = "127.0.0.1",
            "-p" = "8090"
        }
    }

To finish off the installation of this satellite, run the following two
commands on both the satellite and the master::

    $ icinga2 node update-config
    $ service icinga2 restart

The service checks for this satellite should now be visible in the Icinga2
dashboard and you should now have realtime monitoring enabled for your Cuckoo
node.
