class ObservableObject:
    def __init__(self, name, containerid, command, timestamp):
        self.prepared_data = name
        self.containerid = containerid
        self.full_command = command
        self.timestamp = timestamp

    def __lt__(self, other):
        if self.prepared_data < other.prepared_data:
            return True
        return False

    def __eq__(self, other):
        if isinstance(other, list):
            return False
        if self.prepared_data != other.prepared_data or self.containerid != other.containerid:
            return False
        return True