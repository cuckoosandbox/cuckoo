# Copyright (C) 2012 JoseMi Holguin (@j0sm1)
# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import cStringIO
import re
import logging

from cuckoo.common.utils import convert_to_printable

log = logging.getLogger("Processing.Pcap.irc.protocol")


class ircMessage(object):
    """IRC Protocol Request."""

    # Client commands
    __methods_client = dict.fromkeys((
        "PASS", "JOIN", "USER", "OPER", "MODE", "SERVICE", "QUIT", "SQUIT",
        "PART", "TOPIC", "NAMES", "LIST", "INVITE", "KICK", "PRIVMSG",
        "NOTICE", "MOTD", "LUSERS", "VERSION", "STATS", "LINKS", "TIME",
        "CONNECT", "TRACE", "ADMIN", "INFO", "SERVLIST", "SQUERY", "WHO",
        "WHOIS", "WHOWAS", "KILL", "PING", "PONG", "ERROR", "AWAY", "REHASH",
        "DIE", "RESTART", "SUMMON", "USERS", "WALLOPS", "USERHOST", "NICK",
        "ISON"
    ))

    def __init__(self):
        self._messages = []
        # Server commandis : prefix - command - params
        self._sc = {}
        # Client commands : command - params
        self._cc = {}

    def _unpack(self, buf):
        """Extract into a list irc messages of a tcp streams.
        @buf: tcp stream data
        """
        try:
            f = cStringIO.StringIO(buf)
            lines = f.readlines()
        except Exception:
            log.error("Failed reading tcp stream buffer")
            return False

        for element in lines:
            if not re.match("^:", element) is None:
                command = "([a-zA-Z]+|[0-9]{3})"
                params = "(\x20.+)"
                irc_server_msg = re.findall(
                    "(^:[\w+.{}!@|()]+\x20)" + command + params, element
                )
                if irc_server_msg:
                    self._sc["prefix"] = convert_to_printable(irc_server_msg[0][0].strip())
                    self._sc["command"] = convert_to_printable(irc_server_msg[0][1].strip())
                    self._sc["params"] = convert_to_printable(irc_server_msg[0][2].strip())
                    self._sc["type"] = "server"
                    self._messages.append(dict(self._sc))
            else:
                irc_client_msg = re.findall(
                    "([a-zA-Z]+\x20)(.+[\x0a\0x0d])", element
                )
                if irc_client_msg and irc_client_msg[0][0].strip() in self.__methods_client:
                    self._cc["command"] = convert_to_printable(irc_client_msg[0][0].strip())
                    self._cc["params"] = convert_to_printable(irc_client_msg[0][1].strip())
                    self._cc["type"] = "client"
                    self._messages.append(dict(self._cc))

    def getClientMessages(self, buf):
        """Get irc client commands of tcp streams.
        @buf: list of messages
        @return: dictionary of the client messages
        """

        try:
            self._unpack(buf)
        except Exception:
            return None

        entry_cc = []
        for msg in self._messages:
            if msg["type"] == "client":
                entry_cc.append(msg)

        return entry_cc

    def getClientMessagesFilter(self, buf, filters):
        """Get irc client commands of tcp streams.
        @buf: list of messages
        @return: dictionary of the client messages filtered
        """
        try:
            self._unpack(buf)
        except Exception:
            return None

        entry_cc = []

        for msg in self._messages:
            if msg["type"] == "client" and msg["command"] not in filters:
                entry_cc.append(msg)

        return entry_cc

    def getServerMessages(self, buf):
        """Get irc server commands of tcp streams.
        @buf: list of messages
        @return: dictionary of server messages
        """

        try:
            self._unpack(buf)
        except Exception:
            return None

        entry_sc = []

        for msg in self._messages:
            if msg["type"] == "server":
                entry_sc.append(msg)

        return entry_sc

    def getServerMessagesFilter(self, buf, filters):
        """Get irc server commands of tcp streams.
        @buf: list of messages
        @return: dictionary of server messages filtered
        """
        try:
            self._unpack(buf)
        except Exception:
            return None

        entry_sc = []
        for msg in self._messages:
            if msg["type"] == "server" and msg["command"] not in filters:
                entry_sc.append(msg)

        return entry_sc

    def isthereIRC(self, buf):
        """Check if there is irc messages in a stream TCP.
        @buf: stream data
        @return: boolean result
        """

        try:
            self._unpack(buf)
            if self._messages:
                return True
            else:
                return False
        except Exception:
            return False
