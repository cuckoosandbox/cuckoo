=====================
Network Configuration
=====================

Now it's the time to setup the network configuration for your virtual machine.

Windows Settings
================

Before configuring the underlying networking of the virtual machine, you might
want to trick some settings inside Windows itself.

One of the most important things to do is **disabling** *Windows Firewall* and the
*Automatic Updates*. The reason behind this is that they can affect the behavior
of the malware under normal circumstances and that they can pollute the network
analysis performed by Cuckoo, by dropping connections or including unrelevant
requests.

You can do so from Windows' Control Panel as shown in the picture:

    .. image:: ../../_images/screenshots/windows_security.png
        :align: center

Virtual Networking
==================

Now you need to decide how to make your virtual machine able to access Internet
or your local network.

While in previous releases Cuckoo used shared folders to exchange data between
the Host and Guests, from release 0.4 it adopts a custom agent that works
over the network using a simple XMLRPC protocol.

In order to make it work properly you'll have to configure your machine's
network so that the Host and the Guest can communicate.
Test network trying to ping a guest is a good practice, to be sure about
virtual network setup.
Use only static address for your guest, as today Cuckoo doesn't support DHCP and
using it will break your setup.

This stage is very much up to your own requirements and to the
characteristics of your virtualization software.

    .. warning:: Virtual networking errors!
        Virtual networking is a vital component for Cuckoo, you must be really
        sure to get connectivity between host and guest.
        Most of the issues reported by users are related to a wrong setup of
        their networking.
        You you aren't sure about that check your virtualization software
        documentation and test connectivity with ping and telnet.

The recommended setup is using a Host-Only networking layout with proper
forwarding and filtering configuration done with ``iptables`` on the Host.

For example, using VirtualBox, you can enable Internet access to the virtual
machines using the following ``iptables`` rules (assuming that eth0 is your
outgoing interface, vboxnet0 is your virtual interface and 192.168.56.0/24 is
your subnet address)::

    iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A POSTROUTING -t nat -j MASQUERADE

And adding IP forward::

    sysctl -w net.ipv4.ip_forward=1
