import os
import stat
import subprocess

from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT

class Sniffer:
    def __init__(self, tcpdump):
        self.tcpdump = tcpdump
        self.proc = None

    def start(self, interface="eth0", host="", file_path=""):
        if not os.path.exists(self.tcpdump):
            return False

        mode = os.stat(self.tcpdump)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            return False

        if not interface:
            return False

        pargs = [self.tcpdump, '-U', '-q', '-i', interface, '-n', '-s', '1515']
        pargs.extend(['-w', file_path])
        pargs.extend(['not', 'port', str(CUCKOO_GUEST_PORT)])

        if host:
            pargs.extend(['and', 'host', host])

        try:
            self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            return False

        return True

    def stop(self):
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    self.proc.kill()
                except Exception as e:
                    return False

        return True
