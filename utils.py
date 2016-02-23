#!/usr/bin/env python

import uuid
import json
from scapy.all import *  # noqa
from math import log


def generate_uuid():
    return str(uuid.uuid4())


def get_byte_size(n):
    if isinstance(n, str):
        return len(n)
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def test_beacon_data_mapping(message_test_data, beacon_data_mapping_json):
    beacon_data_mapping = json.loads(beacon_data_mapping_json)
    packet = {}

    for packet_field, beacon_fields in beacon_data_mapping:
        packet['packet_protocol'], packet['packet_field'] = \
            packet_field.split(".")

        if not isinstance(beacon_fields, list):
            l = []
            l.append(beacon_fields)
            beacon_fields = l

        for beacon_field in beacon_fields:
            packet['beacon_field'] = message_test_data[beacon_field]
            field_max_size = eval((
                '{packet_protocol}().get_field(\'{packet_field}\')'
                '.i2len(\'{beacon_field}\', \'{beacon_field}\')')
                .format(**packet))

            data_size = get_byte_size(message_test_data[beacon_field])

            if data_size > field_max_size:
                message = "The packet field '%s.%s' has a maximum size of %d. \
                    The message field '%s' is %d byte" % (
                    packet['packet_protocol'],
                    packet['packet_field'],
                    field_max_size,
                    beacon_field,
                    data_size)
                return (False, message)
    return (True, None)


def is_ascii(string):
    """Check if string is all ascii characters"""
    return all(ord(c) < 128 for c in string)

if __name__ == "__main__":
    d = """{ "TCP-sport": "type", "TCP-seq": "uuid",
        "TCP-ack": "data_length", "Raw-load": "data" }"""

    test_beacon_data_mapping(d)
