#!/usr/bin/env python

from collections import OrderedDict
import struct
import re
import binascii
import json

from lpexceptions import MalformedBeacon

# OrderedDict to maintain order of fields when packing the data
#   Available type range: 0x0 - 0xf
# 0x0 : ping
# 0x1 : send data
# 0x2 : get tasking
#  Beacon type field is both message format and message type packed into
# a single byte (format = upper nibble, type = lower nibble)
BEACONS = OrderedDict([
    ('ping', OrderedDict([
        ('type', 0x0),
        ('uuid', '00000000-0000-0000-0000-000000000000')
    ])),
    ('data', OrderedDict([
        ('type', 0x1),
        ('uuid', '00000000-0000-0000-0000-000000000000'),
        ('data_length', 0x0000),
        ('data', None)
    ]))
])
BEACON_TYPES = {}
for beacon_name, beacon_data in BEACONS.iteritems():
    BEACON_TYPES[beacon_name] = beacon_data['type']

# OrderedDict to maintain order of fields when packing the data
#   Available type range: 0x0 - 0xf
# 0x0 : cli
# 0x1 : python
TASKS = OrderedDict([
    ('cli_command', OrderedDict([
        ('type', 0x0),
        ('data_length', 0x0000),
        ('data', None)
    ])),
    ('python', OrderedDict([
        ('type', 0x1),
        ('data_length', 0x0000),
        ('data', None)
    ]))
])
TASK_TYPES = {}
for task_name, task_data in TASKS.iteritems():
    TASK_TYPES[task_name] = task_data['type']

# Message formats
#  Available format range: 0x0 - 0xf
# 0x0 : plain
# 0x1 : base64
MESSAGE_FORMATS = OrderedDict([
    ('plain', 0x0),
    ('base64', 0x1),
    ('xor', 0x2),
])

message_test_data = {
    'type': 0xff,
    'uuid': 0xa2810bec54cf419cbfa2a9cc72dd13fb,
    'data_length': 0xffff,
    'data': 'ls'
}


def xor(data, b = 0x33):
    return ''.join([c ^ b for c in data])

def json_to_beacon(beacon_json):
    return json.loads(beacon_json)


def get_all_beacon_fields_json():
    return json.dumps(get_all_beacon_fields())


def get_all_beacon_fields():
    beacon_fields = []
    for name, fields in BEACONS.iteritems():
        beacon_fields += [
            key for key in fields.keys() if key not in beacon_fields]
    return beacon_fields


def get_all_task_fields_json():
    return json.dumps(get_all_task_fields())


def get_all_task_fields():
    task_fields = []
    for name, fields in TASKS.iteritems():
        task_fields += [
            key for key in fields.keys() if key not in task_fields]
    return task_fields


def get_beacon_by_type(beacon_type):
    for beacon_name, beacon_data in BEACONS.iteritems():
        if beacon_data['type'] == beacon_type:
            return beacon_data
    return None


def get_task_by_type(task_type):
    for task_name, task_data in TASKS.iteritems():
        if task_data['type'] == task_type:
            return task_data
    return None


class Message(object):
    """Base class for all message types"""

    def __init__(self, format=0x0, type=0x0, data=''):
        self.key_list = list()
        self.format = format
        self.type = type
        self.data = data
        self.data_length = len(data)

    def __setattr__(self, key, value):
        """Overriden object method to modify values on update"""
        print "__setattr__: %s =>%s" % (key, value)
        if key == 'type' and isinstance(value, str):
            print "Message.type: %s" % value.encode('hex')
            print "struct.unpack: %s" % struct.unpack('!B', value)
            msgtype = int(struct.unpack('!B', value)[0])
            self['format'] = (msgtype & 0xf0) >> 4
            value = msgtype & 0x0f
            print "Message.type: %d" % value
        elif key == 'format' and isinstance(value, str):
            value = int(struct.unpack('!B', value)[0]) & 0x0f
        elif key == 'data' and value:
            self.data_length = len(value)
        elif key == 'data_length' and isinstance(value, str):
            value = int(struct.unpack('!H', value.zfill(2))[0])
        super(Message, self).__setattr__(key, value)

    def __getattribute__(self, key):
        """Overriden object method to modify return values dynamically"""
        if key == 'type':
            msgformat = super(Message, self).__getattribute__('format')
            msgtype = super(Message, self).__getattribute__('type')
            return (msgformat << 4) | (msgtype) & 0xff
        return super(Message, self).__getattribute__(key)

    def __setitem__(self, key, value):
        """Required method for setting attributes
        like this message['attribute'] = x"""
        if key not in self.keys():
            self.key_list.append(key)
        print "__setitem__: %s =>%s" % (key, value)
        self.__setattr__(key, value)

    def iteritems(self):
        """Required method for iterating over the attributes"""
        return self.__dict__.iteritems()

    def keys(self):
        """Required method for iterating over the attributes"""
        return self.key_list

    def pack(self):
        """Return all Message data packed into string of
        network ordered bytes"""
        return struct.pack('!B', self.type)

    def toJson(self):
        """Dump message in json format"""
        return json.dumps(self.__dict__)

    def __repr__(self):
        return self.toJson()


class Beacon(Message):
    """Beacon message type"""

    def __init__(self, uuid='00000000-0000-0000-0000-000000000000', **kwargs):
        self.uuid = UUID(uuid).string()
        self.external_ip_adress = ''
        super(Beacon, self).__init__(**kwargs)

    def __setattr__(self, key, value):

        if key == 'uuid':
            value = UUID(value).string()
        super(Beacon, self).__setattr__(key, value)

    def pack(self):
        """Return all Beacon data packed into string of
        network ordered bytes"""
        buff = struct.pack('!B16s', self.type, UUID(self.uuid).raw())
        if self.data_length > 0:
            buff += struct.pack('!H', self.data_length)
            buff += struct.pack('!%ss' % self.data_length, self.data)
        return buff


if __name__ == "__main__":
    print BEACON_TYPES
    print TASK_TYPES
