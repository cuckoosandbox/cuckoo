class MachineManager(object):
    def __init__(self):
        pass

    def acquire(self, label=None):
        raise NotImplementedError

    def release(self, label=None):
        raise NotImplementedError

    def start(self, label=None):
        raise NotImplementedError

    def stop(self, label=None):
        raise NotImplementedError
