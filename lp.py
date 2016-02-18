#! /usr/bin/env python
import sys
from scapy.all import *  # noqa
import json

from daemon import Daemon
from datapoller import DataPoller
from filters import get_scapy_filter_from_querybuilder_rules
from utils import get_byte_size
from messages import message_test_data
from messages import Beacon
import api


class BeaconFilterList(list):

    def __init__(self, *args, **kwargs):
        super(BeaconFilterList, self).__init__(*args)
        self.on_add = kwargs.pop('on_add', None)
        self.on_remove = kwargs.pop('on_remove', None)

    def beacon_update(self, list2):

        if self == list2:
            # Beacon Filter queue is up-to-date
            return

        for filter in list2:
            if filter not in self:
                # Execute callback method for New or Updated Beacon Filter
                self.on_add(filter)

        for filter in self:
            if filter not in list2:
                # Execute callback method for Removal of a Beacon Filter
                self.on_remove(filter)


class LP(Daemon):
    """Listening Post (LP) service for receiving and processing Command &
    Control Beacons from implants.

    This LP allows the user to register custom handlers for different packet
    types.
    For example, the user could have a DNS beacon handler that processes
    only DNS packets.

    Attributes:
        verbose:    Enables verbose logging
        handlers:   Stores registered handlers
    """

    def __init__(self, *args, **kwargs):
        """Constructor

        """
        super(LP, self).__init__(*args, **kwargs)
        self.verbose = False
        self.filters = {}
        self.beacon_filters = BeaconFilterList(
            on_add=self._new_beacon_filter_callback,
            on_remove=self._remove_beacon_filter_callback)
        self.task_queue = {}

    def _pkt_handler(self, pkt):
        """Process a packet

        :type pkt: scapy.Packet
        :param pkt: Packet to be processed
        """

        for registered_filter in self.filters:
            packet = filter(registered_filter, pkt)

            if packet:
                # Packet matches a registered filter
                self._log("Packet matches filter: %s" % registered_filter)

                data_map_list = self.filters[registered_filter]

                beacon = self.extract_beacon_from_packet(
                    packet[0], data_map_list)

                print beacon

                self.send_beacon_to_controller(beacon)

    def send_beacon_to_controller(self, beacon):
        api.send_beacon(beacon)

    def _parse_data_map(self, data_map_list):
        data_mapping_dict = {}

        for beacon_data_mapping in data_map_list:

            data_mapping = json.loads(beacon_data_mapping)

            # Figure out which beacon fields are packed into
            # the same packet field
            for packet_field, beacon_field in data_mapping:
                if packet_field in data_mapping_dict:
                    data_mapping_dict[packet_field].append(beacon_field)
                else:
                    data_mapping_dict[packet_field] = [beacon_field]
        return data_mapping_dict

    def extract_beacon_from_packet(self, packet, data_map_list):
        """
        packet: scapy Packet object
        list_of_beacon_data_mappings: ??
        """

        beacon = Beacon()
        beacon.external_ip_address = packet['IP'].src

        mapped_data = self._parse_data_map(data_map_list).iteritems()

        for packet_field, beacon_fields in mapped_data:
            field_protocol, field_subfield = packet_field.split(".")

            # Use scapy to extract the data from the packet field
            packet_field_value = eval(
                "packet['%s'].%s" % (field_protocol, field_subfield))

            if len(beacon_fields) > 1:
                # More than one beacon field within same packet field

                offset = 0
                for beacon_field in beacon_fields:
                    data_size = get_byte_size(
                        message_test_data[beacon_field])
                    if beacon_field == 'data':

                        try:
                            data_size = beacon.data_length
                        except AttributeError:
                            # Normal if Beacon doesn't contain data
                            data_size = 0

                    beacon['%s' % beacon_field] = packet_field_value[
                        offset:offset+data_size]

                    #if beacon_field == 'data_length' and not
                    # (beacon.type & BEACON_TYPES['data']):
                    #    # Stop reading data if the beacon
                    #    # type is not data
                    #    break

                    offset += data_size
            else:
                beacon['%s' % beacon_field] = packet_field_value
        return beacon

    """
    def extract_beacon_from_packet(self, packets, beacon_data_mapping_list):
        # Extract beacon data from packet

        for packet in packets:
            # Iterate over each packet

            for beacon_data_mapping in beacon_data_mapping_list:
                # apply all data mappings registered for this packet

                data_mapping = json.loads(beacon_data_mapping)

                # Figure out which beacon fields are packed into
                # the same packet field
                data_mapping_dict = {}

                for packet_field, beacon_field in data_mapping:
                    if packet_field in data_mapping_dict:
                        data_mapping_dict[packet_field].append(beacon_field)
                    else:
                        data_mapping_dict[packet_field] = [beacon_field]

                # Add extracted data to Beacon object
                beacon = Beacon()
                beacon.external_ip_address = packet['IP'].src

                # Apply each data map to this packet
                mapped_data = data_mapping_dict.iteritems()

                for packet_field, beacon_fields in mapped_data:
                    field_protocol, field_subfield = packet_field.split(".")

                    # Use scapy to extract the data from the packet field
                    packet_field_value = eval(
                        "packet['%s'].%s" % (field_protocol, field_subfield))

                    if len(beacon_fields) > 1:
                        # More than one beacon field within same packet field

                        offset = 0
                        for beacon_field in beacon_fields:
                            data_size = get_byte_size(
                                message_test_data[beacon_field])
                            if beacon_field == 'data':

                                try:
                                    data_size = beacon.data_length
                                except AttributeError:
                                    # Normal if Beacon doesn't contain data
                                    data_size = 0

                            beacon['%s' % beacon_field] = packet_field_value[
                                offset:offset+data_size]

                            #if beacon_field == 'data_length' and not
                            # (beacon.type & BEACON_TYPES['data']):
                            #    # Stop reading data if the beacon
                            #    # type is not data
                            #    break

                            offset += data_size
                    else:
                        beacon['%s' % beacon_field] = packet_field_value
                return beacon
    """

    def _new_beacon_filter_callback(self, filter):
        """Callback method called when a new filter is added to the queue"""
        self._log("Adding Beacon Filter")
        scapy_filter = eval(
            get_scapy_filter_from_querybuilder_rules(filter['beacon_filter']))
        beacon_data_mapping = filter['beacon_data_mapping']
        self.register_filter(scapy_filter, beacon_data_mapping)
        self.beacon_filters.append(filter)

    def _remove_beacon_filter_callback(self, filter):
        """Callback method called when a filter is removed from the queue"""
        self._log("Remove Beacon from the list")
        scapy_filter = eval(
            get_scapy_filter_from_querybuilder_rules(filter['beacon_filter']))
        beacon_data_mapping = filter['beacon_data_mapping']
        self.unregister_filter(scapy_filter, beacon_data_mapping)
        self.beacon_filters.remove(filter)

    def register_filter(self, filter, beacon_data_mapping):
        """Add a new packet filter
        """
        try:
            if beacon_data_mapping not in self.filters[filter]:
                self.filters[filter].append(beacon_data_mapping)
        except KeyError:
            self.filters[filter] = [beacon_data_mapping]

        self._log("Registered new filter: %s" % (filter))

    def unregister_filter(self, filter, beacon_data_mapping):
        """Remove a packet handler from the list of handlers"""
        if len(self.filters[filter]) == 1:
            del self.filters[filter]
        else:
            self.filters[filter].remove(beacon_data_mapping)

    def _log(self, msg):
        """Private logger for messages"""
        if self.verbose:
            sys.stderr.write("%s\n" % str(msg))

    def _start_sniff(self):
        """Start listening for incoming packets"""
        self._log("Starting the packet sniffer")
        sniff(prn=self._pkt_handler, store=0)

    def start_data_poller(self):
        self._log("Starting the data poller")
        self.dp = DataPoller(
            beacon_filters=self.beacon_filters,
            logger=self._log, task_queue=self.task_queue)
        self.dp.start()

    def stop(self):
        self.dp.stop()
        super(LP, self).stop()

    def run(self):
        """Run forever"""
        self.start_data_poller()
        self._start_sniff()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog='Lp')

    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true", default=False)

    parser.add_argument("-d", "--daemon", help="run in background (daemonize)",
                        choices=['start', 'stop', 'restart'],
                        default=False)

    args = parser.parse_args()

    lp = LP('/var/run/lp.pid')
    lp.verbose = args.verbose

    # TCP Handler
    def _handler_tcp(pkt):
        print "Called tcp handler"

    _filter_tcp = lambda p: TCP in p
    #lp.register_handler(_filter_tcp, _handler_tcp)

    # UDP Handler
    def _handler_udp(pkt):
        print "Called udp handler"

    _filter_udp = lambda p: UDP in p
    #lp.register_handler(_filter_udp, _handler_udp)

    if args.daemon == 'start':
        print "Starting"
        lp.start()
    elif args.daemon == 'stop':
        print "Stopping"
        lp.stop()
    elif args.daemon == 'restart':
        print "Restarting"
        lp.restart()
    else:
        lp.run()
