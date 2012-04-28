class GuestManager(object):
    def __init__(self, address, user, password):
        self.address  = address
        self.user     = user
        self.password = password

    def start_analysis(self):
        raise NotImplementedError

    def get_results(self):
        raise NotImplementedError
