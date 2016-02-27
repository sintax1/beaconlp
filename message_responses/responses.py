from scapy.all import *  # noqa
import struct
import json
from messages import (MESSAGE_FORMATS, encode)

def get_all_response_types():
    response_types = [r.response_name for r in BaseResponse.__subclasses__()]
    return zip(response_types, response_types)


def get_response_by_name(name):
    for response in BaseResponse.__subclasses__():
        if response.response_name == name:
            return response
    return None


class BaseResponse(object):

    response_name = "Response"

    def __init__(self, **kwargs):
        for k, v in kwargs:
            self.setattr(k, v)

    def create_response(self, req):
        return req

    def add_response_data(
            self, reply, data, data_mapping, format=MESSAGE_FORMATS['plain']):
        """
        data = {
            'type': 0x0,
            'data_length': 0x0,
            'data': 'string'
        }
        data_mpping = {
            'Raw.load': 'type',
            'Raw.load': 'data_length',
            'Raw.load': 'data'
        }
        """

        data_map = {}
        for packet_field, response_field in data_mapping:
            if packet_field in data_map.keys():
                data_map[packet_field].append(response_field)
            else:
                data_map[packet_field] = [response_field]

        for packet_field, response_fields in data_map.iteritems():
            packet_layer, packet_field = packet_field.split(".")

            buff = ""
            for response_field in response_fields:
                if response_field == 'type':
                    msg_type = ((format << 4) & 0xf0) | (data['type'] & 0x0f)
                    buff += struct.pack('!B', msg_type)
                elif response_field == 'data_length':
                    buff += encode(
                        struct.pack('!H', data['data_length']), format)
                elif response_field == 'data' and data['data']:
                    buff += encode(
                        struct.pack(
                            '!%ss' % data['data_length'], str(data['data'])),
                        format)

            layer_type = eval(packet_layer)
            layer = reply.getlayer(layer_type)
            #print "layer type: %s" % type(layer)
            layer.setfieldval(packet_field, buff)

        #print "Reply Packet:"
        #print reply.show()

    def print_response(self, req):
        response = self.create_response(req.copy())
        print "%s => %s" % (req.summary(), response.summary())


class GenericResponse(BaseResponse):

    response_name = "Generic"

    def create_response(self, req):
        ip = req.getlayer(IP)
        reply = IP(src=ip.dst, dst=ip.src)
        return reply


class ICMPResponse(BaseResponse):

    response_name = "ICMP echo-reply"

    def create_response(self, req):
        ip = req.getlayer(IP)
        icmp = req.getlayer(ICMP)
        icmp.type = 0  # echo-reply
        reply = IP(src=ip.dst, dst=ip.src)/icmp
        return reply


class DNSTXTResponse(BaseResponse):

    response_name = "DNS TXT Record"

    def create_response(self, req):
        ip = req.getlayer(IP)
        udp = req.getlayer(UDP)
        
        dns = req.getlayer(DNS)
        dns_resp = DNS(id=dns.id, ancount=1, qd=dns.qd)
        #print "Request Packet:"
        #print req.show()
        dns_resp.an = DNSRR(rrname=dns.qd.qname,type="TXT",rdata="test")
        reply = IP(dst=ip.src)/UDP(dport=udp.sport, sport=53)/dns_resp
        return reply
