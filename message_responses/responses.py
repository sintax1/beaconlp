from scapy.all import *


def get_all_response_types():
    return [r.response_name for r in BaseResponse.__subclasses__()]


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
    
    def add_response_data(self, reply, data, data_mapping):
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
        for packet_data, response_data in data_mapping.iteritems():
            packet_layer, packet_field = packet_data.split(".")
            layer = reply.getlayer(packet_layer)
            if isinstance(response_data, list):
                response_data = ''.join(response_data)
            layer.setfieldval(packet_field, response_data)
            reply[packet_layer] = layer 


class ICMPResponse(BaseResponse):

    def create_response(self, req):
        ip = req.getlayer(IP)
        icmp = req.getlayer(ICMP)
        icmp.type = 0  # echo-reply
        reply = IP(src=ip.dst, dst=ip.src)/icmp
        return reply


class DNSResponse(BaseResponse):

    def create_response(self):
        pass
