"""
Copyright 2019 Southern California Edison
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

# ! /usr/bin/env python3.6

import base64
import json
import logging
import os
import queue
import signal
import sys
from datetime import datetime
from typing import Dict, List, Tuple, TypeVar, Union
import io

import click
import pyshark
import stix2
from pyshark import FileCapture
from pyshark.packet.layer import Layer
from pyshark.packet.packet import Packet
from stix2 import Bundle
from stix2.base import _Observable
from stix2matcher.matcher import Pattern

import src.stixthread
from src.enip_decoder import EnipHeader, Cip, CipData, CipConnectionManager
from src.cip_decoder import CIPDecoder
from src.arp_decode import ArpPacket
from conf.engine_config import GlobalSettings
from src.stix_observed import StixObservedData

from src.dnp3_decoder import DNP3Decoder

logging.getLogger(__name__)

StixObservableType = TypeVar('StixObservableType', bound=_Observable)
StixExtensionObjectType = TypeVar('StixExtensionObjectType', bound=stix2.base._Extension)
ExtensionArgType = Union[str, int, Dict[str, StixExtensionObjectType]]
DecoderArgsParam = Dict[str, ExtensionArgType]
EnipTypes = Union[EnipHeader, Cip, CipData, CipConnectionManager]

settings = GlobalSettings()
write_bundle = None
pattern_file = None


class FilteringFileCapture(pyshark.FileCapture):
    def __init__(self, pcap_files: List[str], bpf: str = None, out_file: str = None):
        """

        :type pcap_files: List[str]
        :type bpf: str
        :type out_file: str
        """
        super(FilteringFileCapture, self).__init__(pcap_files, display_filter=bpf, output_file=out_file)

        self.logger = logging.getLogger('packetengine.FilteringFileCapture')
        self.bpf_filter = bpf

class PacketDecoder:
    def __init__(self):
        self.highest_protocol = None
        self.layers = {}
        self.layers = {}
        self.refcount = 0
        self.sniff_timestamp = 0
        self.logger = logging.getLogger('packetengine.PacketDecoder')

    def decode(self, packet):
        """

        :param packet:
        :type packet: pyshark.packet.packet.Packet
        :return:
        :rtype: Tuple[Dict[str, Dict[str, str]], Dict[str, StixObservableType]]
        """
        self.logger.debug(' Decoding Packet: %s', packet)
        self.highest_protocol, self.layers = PacketDecoder.get_layers(packet)
        self.sniff_timestamp = float(packet.sniff_timestamp)
        if 'ip' in self.layers:
            args, objects = self.decode_ip(packet)
        elif 'arp' in self.layers:
            source_mac = stix2.MACAddress(value=self.layers['eth']['src'])
            dest_mac = stix2.MACAddress(value=self.layers['eth']['dst'])
            self.refcount = 2
            objects = {
                "0": source_mac,
                "1": dest_mac
            }
            arp_ext = ArpPacket(**self.layers['arp'])
            args = {'_valid_refs': {"0": 'mac-addr', "1": 'mac-addr'},
                    'src_ref': "0",
                    'dst_ref': "1",
                    'protocols': 'arp',
                    'extensions': {'x-arp-ext': arp_ext}}
        else:
            args = {}
            objects = {}
        return args, objects

    def decode_ip(self, packet):
        """

        :param packet:
        :type packet: pyshark.packet.packet.Packet
        :return:
        :rtype: Tuple[Dict[str, Dict[str, str]], Dict[str, StixObservableType]]
        """
        # TODO add ipv6 support
        source_ip = stix2.IPv4Address(value=self.layers['ip']['src'])
        dest_ip = stix2.IPv4Address(value=self.layers['ip']['dst'])
        objects = {
            "0": source_ip,
            "1": dest_ip
        }
        args = {
            '_valid_refs': {"0": 'ipv4-addr', "1": 'ipv4-addr'},
            'src_ref': "0",
            'dst_ref': "1"
        }
        if 'tcp' in self.layers:
            args, objects = self.decode_tcp(packet, args, objects)
        elif 'udp' in self.layers:
            args, objects = self.decode_udp(packet, args, objects)
        elif 'icmp' in self.layers:
            args, objects = self.decode_icmp(packet, args, objects)
        else:
            return {}, {}
        return args, objects

    def decode_icmp(self, packet, args, objects):
        """

        :param packet:
        :type packet: pyshark.packet.packet.Packet
        :param args:
        :type args: DecoderArgsParam
        :param objects:
        :type objects: Dict[str, StixObservableType]) -> Tuple[DecoderArgsParam, Dict[str, StixObservableType]]
        :return:
        :rtype:
        """
        args['protocols'] = "icmp"
        self.refcount = 2
        icmp_code = self.layers['icmp']['code'].fields[0].raw_value
        icmp_type = self.layers['icmp']['type'].fields[0].raw_value
        icmp_ext = stix2.ICMPExt(icmp_code_hex=icmp_code, icmp_type_hex=icmp_type)
        args['extensions'] = {'icmp-ext': icmp_ext}
        return args, objects

    # Add DNP3 support. Bryce 20190909
    def decode_tcp(self, packet: pyshark.packet.packet.Packet, args: Dict[str, Dict[str, str]],
                   objects: Dict[str, stix2.v20.observables.IPv4Address]) -> \
            Tuple[Dict[str, Dict[str, str]], Dict[str, stix2.v20.observables.IPv4Address]]:
        """

        :param packet:
        :type packet: pyshark.packet.packet.Packet
        :param args:
        :type args: Union[Dict[str, Dict[str, str]], str]
        :param objects:
        :type objects: Dict[str, stix2.v20.observables.IPv4Address]
        :return:
        :rtype: Tuple[Dict[str, Dict[str, str]], Dict[str, stix2.v20.observables.IPv4Address]]
        """
        args['src_port'] = self.layers['tcp']['srcport']
        args['dst_port'] = self.layers['tcp']['dstport']
        args['protocols'] = "tcp"
        self.refcount = 2
        artifact = self.build_payload_artifact(packet)
        if artifact is not None:
            # objects[str(refcount)] = artifact
            artifact_ref = str(self.refcount)
            self.refcount += 1
        else:
            artifact_ref = None
        if 'http' in self.layers:
            http_ext = self.build_http_ext(self.layers['http'], artifact_ref)
            # print(http_ext)
        else:
            http_ext = None
        enip_extensions = None
        if 'enip' in self.layers:
            enip_decode = CIPDecoder(self)
            enip_extensions = enip_decode.decode(packet)  # type: List[EnipTypes]
        dnp3_extensions = None
        if 'dnp3' in self.layers:
            # print(packet)
            dnp3_decode = DNP3Decoder(self)
            dnp3_extensions = dnp3_decode.decode(packet)    # Type: List[Dnp3Types]

        if http_ext is not None:
            args['extensions'] = {"http-request-ext": http_ext}
        if artifact_ref is not None:
            args['_valid_refs'][artifact_ref] = 'artifact'
            args['src_payload_ref'] = artifact_ref
            objects[artifact_ref] = artifact
        if enip_extensions is not None:
            if 'extensions' not in args:
                args['extensions'] = {}
            for enip in enip_extensions:
                args['extensions'][enip._type] = enip
        if dnp3_extensions is not None:
            if 'extensions' not in args:
                args['extensions'] = {}
            for dnp3 in dnp3_extensions:
                args['extensions'][dnp3._type] = dnp3

        return args, objects

    def decode_udp(self, packet, args, objects):
        """

        :param packet:
        :type packet: pyshark.packet.packet.Packet
        :param args:
        :type args: Dict[str, Dict[str, str]]
        :param objects:
        :type objects: Dict[str, stix2.v20.observables.IPv4Address]
        :return:
        :rtype: Tuple[Dict[str, Dict[str, str]], Dict[str, stix2.v20.observables.IPv4Address]]
        """
        args['src_port'] = self.layers['udp']['srcport']
        args['dst_port'] = self.layers['udp']['dstport']
        args['protocols'] = "udp"
        self.refcount = 2
        artifact = self.build_payload_artifact(packet)
        if artifact is not None:
            # objects[str(refcount)] = artifact
            artifact_ref = str(self.refcount)
            self.refcount += 1
        else:
            artifact_ref = None
        if artifact_ref is not None:
            args['_valid_refs'][artifact_ref] = 'artifact'
            args['src_payload_ref'] = artifact_ref
            objects[artifact_ref] = artifact
        return args, objects

    def build_http_ext(self, packet_layer, artifact_ref=None):
        """
        _properties.update([
            ('request_method', StringProperty(required=True)),
            ('request_value', StringProperty(required=True)),
            ('request_version', StringProperty()),
            ('request_header', DictionaryProperty()),
            ('message_body_length', IntegerProperty()),
            ('message_body_data_ref', ObjectReferenceProperty(valid_types='artifact')),
        ])

        :return:
        :rtype: stix2.HTTPRequestExt
        :param artifact_ref: The integer which will be the reference index for the artifact in the final stix object
        :type artifact_ref: Optional[str]
        :type packet_layer: Layer
        """
        http_ext = None
        if 'request_method' in packet_layer and artifact_ref is None:
            http_ext = stix2.HTTPRequestExt(
                request_method=packet_layer.get('request_method', None),
                request_value=packet_layer.get('request_uri'),
                request_version=packet_layer.get('request_version'),
                request_header=None,
                message_body_length=None,
                message_body_data_ref=None)
        elif 'request_method' in packet_layer and artifact_ref is not None:
            http_ext = stix2.HTTPRequestExt(
                request_method=packet_layer.get('request_method', None),
                request_value=packet_layer.get('request_uri'),
                request_version=packet_layer.get('request_version'),
                request_header=None,
                message_body_length=None,
                message_body_data_ref=artifact_ref)
        return http_ext

    def build_payload_artifact(self, packet):
        """

        :type packet: Packet
        """
        layers = self.get_layers(packet)[1]
        if 'data' in layers:
            payload_bin = packet.data.get_field('tcp_reassembled_data')
        elif 'tcp' in layers:
            # payload_bin = packet.tcp.get_field('segment_data')
            payload_bin = packet.tcp.get_field('payload')
            # layers['tcp'].get_field('payload')
        elif 'udp' in layers:
            # print(layers['udp'])
            payload_bin = packet.udp.get_field('payload')
        else:
            payload_bin = None
        if payload_bin is not None:
            payload_bin = base64.b64encode(bytes([int(x, 16) for x in payload_bin.split(':')]))
            mime_type = 'text/plain'
            artifact = stix2.Artifact(payload_bin=payload_bin, mime_type=mime_type)
            # print(artifact)
            return artifact
        else:
            return None

    @staticmethod
    def get_highest_protocol(packet):
        """

        :type packet: Packet
        """
        for layer in reversed(packet.layers):
            if layer.layer_name in settings.EXCLUDED_PROTOCOLS:
                continue
            else:
                return str.replace(layer.layer_name, '.', '-')

    @staticmethod
    def get_layer_fields(layer):
        """

        :type layer: pyshark.packet.layer.Layer
        """
        layer_fields = {}
        for field_name in layer.field_names:
            if len(field_name) > 0:
                layer_fields[field_name] = getattr(layer, field_name)
        return layer_fields

    @staticmethod
    def get_layers(packet):
        """

        :type packet: Packet
        """
        n = len(packet.layers)
        # field_names = packet_util.get_all_field_names(packet)  # type: Set[str]

        highest_protocol = PacketDecoder.get_highest_protocol(packet)
        layers = {packet.layers[0].layer_name: PacketDecoder.get_layer_fields(packet.layers[0])}

        # Link layer
        layers[packet.layers[0].layer_name]['level'] = 0
        layer_above_transport = 0

        # Get the rest of the layers
        for i in range(1, n):
            layer = packet.layers[i]

            # Network layer - ARP
            if layer.layer_name == 'arp':
                layers[layer.layer_name] = PacketDecoder.get_layer_fields(layer)
                layers[layer.layer_name]['level'] = i
                return highest_protocol, layers

            # Network layer - IP or IPv6
            elif layer.layer_name == 'ip' or layer.layer_name == 'ipv6':
                layers[layer.layer_name] = PacketDecoder.get_layer_fields(layer)
                layers[layer.layer_name]['level'] = i

            # Transport layer - TCP, UDP, ICMP, IGMP, IDMP, or ESP
            elif layer.layer_name in ['tcp', 'udp', 'icmp', 'igmp', 'idmp', 'esp']:
                layers[layer.layer_name] = PacketDecoder.get_layer_fields(layer)
                layers[layer.layer_name]['level'] = i
                if highest_protocol in ['tcp', 'udp', 'icmp', 'esp']:
                    return highest_protocol, layers
                layer_above_transport = i + 1
                break

            # Additional layers
            else:
                layers[layer.layer_name] = PacketDecoder.get_layer_fields(layer)
                layers[layer.layer_name]['level'] = i

        for j in range(layer_above_transport, n):
            layer = packet.layers[j]

            # Application layer
            if layer.layer_name == highest_protocol:
                layers[layer.layer_name] = PacketDecoder.get_layer_fields(layer)
                layers[layer.layer_name]['level'] = i

            # Additional application layer data
            else:
                layer_name = str.replace(layer.layer_name, '.', '-')
                if layer_name == '_ws-malformed':
                    layer_name = '[Malformed_Packet]'
                layers[layer_name] = PacketDecoder.get_layer_fields(layer)
                layers[layer_name]['level'] = i

        return highest_protocol, layers


def dump_packets(capture, count=0):
    """

    :param count: number of packets to process, 0 means collect forever
    :type count: int
    :param capture: pyshark.LiveCapture or pyshark.FileCapture instance
    :type capture: Union[pyshark.FileCapture, pyshark.LiveCapture]
    """
    pkt_no = 1
    for packet in capture:  # type: Packet
        highest_protocol, layers = PacketDecoder.get_layers(packet)
        sniff_timestamp = float(packet.sniff_timestamp)
        print('Packet no.', pkt_no)
        print('* protocol        -', highest_protocol)
        print('* sniff date UTC  -', datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%dT%H:%M:%S+0000'))
        print('* sniff timestamp -', sniff_timestamp)
        print('* layers')
        for key in layers:
            print('\t', key, layers[key])
        print()
        pkt_no += 1
        # if 'ip' not in layers or 'tcp' not in layers:
        #     print('Dumping of {} not supported'.format(highest_protocol))
        #     print()
        #     continue

        if 0 < count < pkt_no:
            return


def live_capture(nic, bpf, outfile, count=0, dump=False, display_filter=None):
    """

    :param display_filter:
    :param dump:
    :type dump: bool
    :type nic: str
    :type bpf: str
    :type outfile: str
    :type count: int
    """
    try:
        # es = None
        # if node is not None:
        #     es = Elasticsearch(node)

        capture = pyshark.LiveCapture(interface=nic, bpf_filter=bpf, output_file=outfile, display_filter=display_filter)
        if not dump:
            decode_packets(capture, count)
        else:
            dump_packets(capture, count)

    except Exception as e:
        logging.error(e)
        raise e


def decode_packets(capture, count):
    """

    :type count: int
    :type capture: Union[pyshark.LiveCapture, pyshark.FileCapture]
    """
    pkt_no = 0
    all_observed = []
    observed_objs = []
    decoder = PacketDecoder()
    global off_line
    global write_bundle
    global pattern_file
    pattern_list = []
    if pattern_file is not None:
        try:
            with io.open(pattern_file, 'r') as patterns_in:
                for pattern in patterns_in:
                    pattern = pattern.strip()
                    if not pattern:
                        continue  # skip blank lines
                    if pattern[0] == u"#":
                        continue  # skip commented out lines
                    escaped_pattern = pattern.encode("unicode_escape").decode("ascii")
                    print(escaped_pattern)
                    pattern_list.append(Pattern(escaped_pattern))
        except PermissionError as e:
            raise e

    for i in range(4):
        t = src.stixthread.STIXPoster(i, obj_queue)
        threads.append(t)
        t.start()

    for packet in capture:
        pkt_no += 1
        sniff_timestamp = float(packet.sniff_timestamp)
        args, objects = decoder.decode(packet)
        if not len(args):
            continue
        logging.debug("args: %s", args)
        logging.debug("objects: %s", objects)
        net_traffic = stix2.NetworkTraffic(**args)
        objects[str(decoder.refcount)] = net_traffic
        decoder.refcount += 1
        device = 'device--' + settings.get_devuuid(online=not off_line)

        observed = StixObservedData(first_observed=str(datetime.utcfromtimestamp(sniff_timestamp)),
                                   last_observed=str(datetime.utcfromtimestamp(sniff_timestamp)),
                                   number_observed=1, objects=objects, device_ref=device)
        print(observed)     # Debug
        # all_observed.append(json.loads(str(observed)))
        if len(pattern_list):
            matches = []
            matched = False
            for p in pattern_list:
                matches = p.match([json.loads(observed.serialize())])
                if len(matches):
                    matched = True
                    # print('matched: ', observed.serialize())
            if not matched:
                observed = None

        if observed:
            logging.debug(observed)
            observed_objs.append(observed)
            if not off_line:
                print('Putting object into queue')
                obj_queue.put(observed)

        if 0 > count > pkt_no:
            break
    obj_queue.join()
    for t in threads:
        t.stop()
        t.join()
    if write_bundle is not None:
        try:
            fp = open(write_bundle, 'w')
        except PermissionError as e:
            raise e
        else:
            with fp:
                stix_bundle = Bundle(*observed_objs, allow_custom=True)
                fp.writelines(stix_bundle.serialize(pretty=True))
                fp.close()

def file_capture(pcap_files, bpf, out_file, count=0, dump=False):
    """

    :param dump: Dump to stdout if true, does not send packets
    :type dump: bool
    :type count: int
    :type out_file: str
    :type bpf: str
    :type pcap_files: List[str]
    """
    # try:
    # es = None
    # if node is not None:
    #     es = Elasticsearch(node)

    logging.debug('Loading packet capture file(s)')
    for pcap_file in pcap_files:
        logging.debug("Pcap file is: %s", pcap_file)
        capture = FileCapture(pcap_file, bpf, out_file)

        if not dump:
            decode_packets(capture, count)
        else:
            dump_packets(capture, count)


def list_interfaces():
    """
    Returns list of network interfaces (nic)

    :return: None
    :rtype: None
    """
    proc = os.popen('tshark -D')  # Note tshark must be in $PATH
    tshark_out = proc.read()
    interfaces = tshark_out.splitlines()
    for i in range(len(interfaces)):
        interface = interfaces[i].strip(str(i + 1) + '.')
        print(interface)


def interrupt_handler(signum, frame):
    """

    :param signum:
    :type signum: int
    :param frame:
    :type frame: int
    """
    print()
    print('Packet capture interrupted. Signal: {} Frame: {}'.format(signum, frame))
    for t in threads:
        t.stop()
        t.join()
    print('Done')
    sys.exit()


off_line = False
threads = []
obj_queue = queue.Queue()

@click.command()
@click.option('--interface', '-i', default=None,
              help='Network interface for live capture (default=None, if file or dir specified)')
@click.option('--read', '-r', default=None,
              help='Read from PCAP file for file capture (default=None, if interface specified)')
@click.option('--in_dir', '-d', default=None,
              help='PCAP directory to read multiple files (default=None, if interface specified)')
@click.option('--display_filter', default=None, help='Wireshark display filter for live capture (default=all packets)')
@click.option('--bpf', '-f', default=None, help='BPF for live capture (default=all packets)')
@click.option('--count', '-c', default=0,
              help='Number of packets to capture during live capture (default=0, capture indefinitely)')
@click.option('--interfaces', '-l', is_flag=True, help='List the network interfaces')
@click.option('--out', '-o', default=None, help='Filename to write captured packets in pcap format, default is None')
@click.option('--dump', is_flag=True, flag_value=True,
              help='Dump decoded packets to stdout, does not send packets to stix monitor')
@click.option('--debug', is_flag=True, flag_value=True, help='Enable DEBUG logging')
@click.option('--offline', is_flag=True, flag_value=True, help='Do not attempt to send data to stix monitor')
@click.option('--stix_mon', '-t', default=None, help='IP address or resolvable name of stix monitor')
@click.option('--port', '-p', default=None, help='Port where stix monitor is listening')
@click.option('--bundle', default=None, help='Filename: Write a bundle of all observed data objects to file')
@click.option('--patterns', default=None, help='File containing stix2 patterns to match.  Only packets matching '
                                               'patterns will be sent.')
def main(interface, read, in_dir, display_filter, bpf, count, interfaces, out, dump, debug, offline, stix_mon, port, bundle, patterns):
    """

    :param bpf:
    :param patterns:
    :param display_filter:
    :param bundle:
    :type bundle:
    :param interface:
    :type interface:
    :param read:
    :type read:
    :param in_dir:
    :type in_dir:
    :param count:
    :type count:
    :param interfaces:
    :type interfaces:
    :param out:
    :type out:
    :param dump:
    :type dump:
    :param debug:
    :type debug:
    :type offline:
    :param offline:
    :param stix_mon:
    :type stix_mon:
    :param port:
    :type port:
    """
    # Make sure Python version is 3.5.x or greater
    if sys.version_info.major != 3:
        raise Exception('Must be using Python 3')
    if sys.version_info.minor < 5:
        raise Exception('Must be using Python 3 version 3.5.x or greater')

    global off_line
    global settings
    global write_bundle
    global pattern_file
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    logging.debug('Argument values:')
    logging.debug('Interface: %s', interface)
    logging.debug('Read: %s', read)
    logging.debug('in_dir: %s', in_dir)
    logging.debug('bpf: %s', bpf)
    logging.debug('display_filter: %s', display_filter)
    logging.debug('count: %d', count)
    logging.debug('interfaces (-l): %s', interfaces)
    logging.debug('out: %s', out)
    logging.debug('dump: %s', dump)
    logging.debug('debug: %s', debug)

    if offline:
        off_line = True
    else:
        stix_mon = settings.API_HOST
        port = settings.API_PORT

    if interfaces:
        list_interfaces()
        sys.exit(0)

    if interface is None and read is None and out is None:
        print('You must specify either file or live capture')
        sys.exit(1)
    if interface and (read or in_dir):
        print('Only specify one of --read, -r, --interface, -i, --in_dir, -d')
        sys.exit(1)

    if bundle:
        write_bundle = bundle

    if patterns:
        pattern_file = patterns

    if stix_mon and not off_line:
        settings.API_HOST = stix_mon

    if port and not off_line:
        settings.API_PORT = port

    if interface:
        settings.SNIFFER_INTERFACE = interface
        live_capture(interface, bpf, out, count, display_filter)
        sys.exit(0)

    if read:
        file_capture([read], display_filter, out, count, dump)

    if in_dir:
        pcap_files = []
        files = os.listdir(in_dir)
        files.sort()
        for file in files:
            if in_dir.find('/') > 0:
                pcap_files.append(in_dir + file)
            else:
                pcap_files.append(in_dir + '/' + file)
        file_capture(pcap_files, display_filter, out, count, dump)

    signal.signal(signal.SIGINT, interrupt_handler)


if __name__ == "__main__":
    main()
