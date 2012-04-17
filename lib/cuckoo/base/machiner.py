class BaseMachiner:
    def __init__(self):
        pass

    def prepare(self):
        raise NotImplementedError

    def get_machine(self, label=None):
        raise NotImplementedError

    def start(self, label=None):
        raise NotImplementedError

    def stop(self, label=None):
        raise NotImplementedError
