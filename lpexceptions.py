class MalformedBeacon(Exception):
    def __init__(self, field, value):
        self.field = field
        self.value = value

    def __str__(self):
        return repr("%s: %s" % (self.field, self.value))
