#!/usr/bin/env python

from scapy.all import *  # noqa
from collections import OrderedDict
import json


def get_all_packet_types():
    """Generate a dictionary of all packet layer names and layer field names"""

    packet_types = OrderedDict()

    for packet in sorted(Packet.__subclasses__(), key=lambda x: x.__name__):
        if packet.__name__.startswith("_"):
            continue

        fields = []
        for field in packet.fields_desc:
            fields.append(field.name)
        packet_types[packet.__name__] = fields

    return packet_types


def get_all_packet_fields():
    """Generate a list of all packet fields"""
    packet_types = get_all_packet_types()
    packet_fields = []

    for type, fields in packet_types.iteritems():
        for field in list(set(fields)):
            packet_field = '%s.%s' % (type, field)
            packet_fields.append(packet_field)

    return packet_fields


def get_querybuilder_filters_json():
    """Generate a dictionary of all packet layer names and layer
        field names in the querybuilder required format
    """

    filters = []

    for packet_type, packet_fields in get_all_packet_types().iteritems():

        for field in list(set(packet_fields)):
            filter = {
                'id': "%s-%s" % (packet_type, field),
                'field': 'filter',
                'label': "%s -> %s" % (packet_type, field),
                'type': 'string',
                'operators': ['equal', 'not_equal'],
                'optgroup': packet_type
            }

            filters.append(filter)

    filters_json = json.dumps(
        filters, sort_keys=True, indent=4, separators=(',', ': '))
    return filters_json


def _querybuilder_rule_to_scapy_filter(rules):
    """Private method.
        Convert Single jQuery QueryBuilder filter rule to scapy filter
    """

    operators = {
        'equal': "==",
        'not-equal': "!=",
    }

    condition = rules['condition'].lower()
    rule_list = rules['rules']
    scapy_filter = ""

    for i in range(len(rule_list)):
        rule = rule_list[i]

        if 'rules' in rule.keys():
            scapy_filter += _querybuilder_rule_to_scapy_filter(rule)
        else:
            if rule['value'].isdigit():
                rule['value'] = int(rule['value'])
            else:
                rule['value'] = "'%s'" % rule['value']
            rule['protocol'], rule['field'] = rule['id'].split("-")
            rule['operator'] = operators[rule['operator']]
            scapy_filter += """({protocol} in p and (p['{protocol}'].{field}
            {operator} {value}))""".format(**rule)

        if i < len(rule_list)-1:
            scapy_filter += " %s " % condition

    #return "lambda p: (%s)" % scapy_filter
    return scapy_filter


def get_scapy_filter_from_querybuilder_rules(querybuilder_rules):
    """Convert jQuery QueryBuilder filter rules to scapy filter"""

    filter_rules = json.loads(querybuilder_rules)

    return "lambda p: (%s)" % _querybuilder_rule_to_scapy_filter(filter_rules)
