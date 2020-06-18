"""
Copyright 2019 Southern California Edison
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""
import logging
import os
import sys
from typing import List, Union

from stix2 import NetworkTraffic, properties, CustomExtension


"""
Layers from pyshark...
***OPEN SESSION (attacker->PLC):
enip {
    'command': '0x00000065',   // Register Session
    'length': '4', 
    'session': '0x00000000', 
    'status': '0x00000000', 
    'context': '00:00:00:00:00:00:00:00', 
    'options': '0x00000000', 
    'rs_version': '1', 
    'rs_flags': '0x00000000', 
    'level': 2
}

***SUCCESS (from PLC):
enip {
    'command': '0x00000065',  // Register Session
    'length': '4', 
    'session': '0x12020200',  // Note Session ID returned here 
    'status': '0x00000000', 
    'context': '00:00:00:00:00:00:00:00', 
    'options': '0x00000000', 
    'rs_version': '1', 
    'rs_flags': '0x00000000', 
    'level': 2
}

*** Force Command to Open a breaker:
enip {
    'command': '0x0000006f',  // Unconnected Send.  NOTE: PLC<->HMI dataflow uses 0x70 Connected Send
    'length': '60',
    'session': '0x12020200',
    'status': '0x00000000',
    'context': '00:00:00:00:00:00:00:00',
    'options': '0x00000000', 
    'srrd_iface': '0x00000000', 
    'timeout': '0', 
    'cpf_itemcount': '2', 
    'cpf_typeid': '0x00000000', 
    'cpf_length': '0', 
    'level': 2
}
cip {
    'service': '0x00000052', 
    'rr': '0x00000000', 
    'sc': '0x00000052', 
    'request_path_size': '2', 
    'epath': '20:06:24:01', 
    'path_segment': '0x00000020', 
    'path_segment_type': '1', 
    'logical_segment_type': '0', 
    'logical_segment_format': '0', 
    'class': '6', 
    'instance': '0x00000001', 
    'level': 2
}
cipcm {
    'cip_rr': '0x00000000', 
    'cip_cm_sc': '0x00000052', 
    'cip_cm_priority': '0', 
    'cip_cm_tick_time': '5', 
    'cip_cm_timeout_tick': '157', 
    'cip_cm_timeout': '5024', 
    'cip_cm_msg_req_size': '29', 
    'cip_service': '0x00000053', 
    'cip_sc': '0x00000053', 
    'cip_request_path_size': '9', 
    'cip_epath': '91:0f:48:4d:49:5f:58:59:4f:5f:42:6b:72:5f:4d:4c:31:00', 
    'cip_path_segment': '0x00000091', 
    'cip_path_segment_type': '4', 
    'cip_data_segment_type': '17', 
    'cip_data_segment_size': '15', 
    'cip_symbol': 'HMI_XYO_Bkr_ML1',  // Tells the PLC which tag 
    'cip_data': 'c1:00:01:00:00:00:00:00:01',  // Data to write to Tag, the last 4 bytes are the value
    'cip_pad': '0x00000000', 
    'cip_cm_route_path_size': '1', 
    'cip_reserved': '0x00000000', 
    'cip_ex_linkaddress': '0', 
    'cip_port': '1', 
    'cip_linkaddress_byte': '0', 
    'level': 2
}

*** SUCCESS FROM PLC:
enip {
    'command': '0x0000006f', 
    'length': '20', 
    'session': '0x12020200', 
    'status': '0x00000000', 
    'context': '00:00:00:00:00:00:00:00', 
    'options': '0x00000000', 
    'srrd_iface': '0x00000000', 
    'timeout': '0', 
    'cpf_itemcount': '2', 
    'cpf_typeid': '0x00000000', 
    'cpf_length': '0', 
    'response_to': '9', 
    'time': '0.008809000', 
    'level': 2
}
cip {
    'service': '0x000000d3', 
    'rr': '0x00000001', enip->cip->response
    'sc': '0x00000053', enip->cip->service
    'genstat': '0', 
    'addstat_size': '0', 
    'request_path_size': '2', 
    'path_segment': '0x00000020', 
    'path_segment_type': '1', 
    'logical_segment_type': '0', 
    'logical_segment_format': '0', 
    'class': '6', 
    'instance': '0x00000001', 
    'level': 2
}
cipcm {
    'cip_cm_sc': '0x00000052', 
    'cip_request_path_size': '9', 
    'cip_path_segment': '0x00000091', 
    'cip_path_segment_type': '4', 
    'cip_data_segment_type': '17', 
    'cip_symbol': 'HMI_XYO_Bkr_ML3', 
    'level': 2
}


"""

plc_hmi = "ip.addr==192.168.1.150 && ip.addr==192.168.1.151"
attacker_plc = "ip.addr==192.168.1.151 && ip.addr==192.168.1.200"


@CustomExtension(NetworkTraffic, 'x-enip-header', [
    ('command', properties.IntegerProperty(required=True)),
    ('length', properties.IntegerProperty(required=True)),
    ('session', properties.IntegerProperty(required=True)),
    ('status', properties.IntegerProperty(required=True)),
    ('context', properties.HexProperty(required=True)),
    ('options', properties.IntegerProperty(required=True)),
    ('rs_version', properties.IntegerProperty()),
    ('rs_flags', properties.IntegerProperty()),
    ('level', properties.IntegerProperty()),
    ('srrd_iface', properties.IntegerProperty()),
    ('timeout', properties.IntegerProperty()),
    ('cpf_itemcount', properties.IntegerProperty()),
    ('cpf.:ype_id', properties.IntegerProperty()),
    ('cpf_length', properties.IntegerProperty()),
    ('cpf_typeid', properties.IntegerProperty()),
    ('cpf_cai_connid', properties.IntegerProperty()),
    ('cpf_cdi_seqcnt', properties.IntegerProperty()),
    ('sud_iface', properties.IntegerProperty())
])
class EnipHeader:
    x = 1


props = ['attribute', 'id_conf', 'id_device_type', 'id_ext', 'id_ext2', 'id_major_fault1', 'id_major_fault2',
         'id_major_rev', 'id_minor_fault1', 'id_minor_fault2', 'id_minor_rev', 'id_owned', 'id_product_code',
         'id_serial_number', 'id_status', 'id_vendor_id', 'getlist_attr_count', 'msp_num_services', 'msp_offset',
         'getlist_attr_status']

more = [(n, properties.IntegerProperty()) for n in props]


@CustomExtension(NetworkTraffic, 'x-common-industrial-protocol', [
    ('service', properties.IntegerProperty()),
    ('class', properties.IntegerProperty()),
    ('epath', properties.HexProperty()),
    ('instance', properties.IntegerProperty()),
    ('logical_segment_format', properties.IntegerProperty()),
    ('logical_segment_type', properties.IntegerProperty()),
    ('path_segment', properties.IntegerProperty()),
    ('path_segment_type', properties.IntegerProperty()),
    ('request_path_size', properties.IntegerProperty()),
    ('cip_response', properties.IntegerProperty()),
    ('cip_service', properties.IntegerProperty()),
    ('addstat_size', properties.IntegerProperty()),
    ('genstat', properties.IntegerProperty()),
    ('id_product_name', properties.StringProperty()),
    ('data', properties.HexProperty()),
    *more
])
class Cip:
    pass


@CustomExtension(NetworkTraffic, 'x-cip-command-specific-data', [
    ('cip_data', properties.HexProperty())
])
class CipData:
    pass


# settings: GlobalSettings = GlobalSettings()
cmprops = ['cip_cm_msg_req_size', 'cip_cm_priority', 'cip_cm_route_path_size', 'cip_cm_sc', 'cip_cm_tick_time',
           'cip_cm_timeout', 'cip_cm_timeout_tick', 'cip_data_segment_size', 'cip_data_segment_type',
           'cip_ex_linkaddress', 'cip_linkaddress_byte', 'cip_pad', 'cip_path_segment',
           'cip_path_segment_type', 'cip_port', 'cip_request_path_size', 'cip_reserved', 'cip_rr', 'cip_sc',
           'cip_service', ]
# cmpropdefs = dict([(n, properties.IntegerProperty()) for n in cmprops])
cmpropdefs = [(n, properties.IntegerProperty()) for n in cmprops]


@CustomExtension(NetworkTraffic, 'x-cip-connection-manager', [
    *cmpropdefs,
    ('cip_data', properties.HexProperty()),
    ('cip_epath', properties.HexProperty()),
    ('cip_symbol', properties.StringProperty())
])
class CipConnectionManager:
    pass




EnipTypes = List[Union[
        EnipHeader,
        Cip,
        CipData,
        CipConnectionManager]]

if __name__ == '__main__':
    from cip_decoder import CIPDecoder
    from packetengine import FilteringFileCapture
    if len(sys.argv) == 1:
        print(f"{__file__} Error: Supply a pcap file as an argument")
        sys.exit(1)
    pcap_file = sys.argv[1]
    logging.debug("Pcap file is: %s", pcap_file)
    stats = os.stat(pcap_file)
    capture = FilteringFileCapture(pcap_file, "port 44818")
    count = 1
    cipdecoder = CIPDecoder()
    all_observed = []
    objects = []
    for pkt in capture:
        objects = cipdecoder.decode(pkt)

    for o in objects:
        print(str(o))
