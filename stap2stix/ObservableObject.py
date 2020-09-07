class ObservableObject:
    def __init__(self, name, containerid, command, timestamp):
        self.name = name
        self.containerid = containerid
        self.command = command
        self.timestamp = timestamp

    def __lt__(self, other):
        if self.name < other.name:
            return True
        return False

    def __eq__(self, other):
        if isinstance(other, list):
            return False
        if self.name != other.name or self.containerid != other.containerid:
            return False
        return True