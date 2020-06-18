"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

__version__ = '1.0.0'

import argparse
import datetime
import json
import logging
import requests
import socket
import socketserver
import sys
import time
import urllib3
import uuid
import textwrap

urllib3.disable_warnings()

LOG_FILE = ''
SEND_MODE = True
DISPLAY_MODE = True

logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='', filename=LOG_FILE, filemode='a')


def generateUUID():
    return str(uuid.uuid4())


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Class for Syslog Handler of UDP socket server"""

    #def __init__(self, stixmon_ip, stixmon_port, syslog_port):
    #    self.stixmon_ip = stixmon_ip
    #    self.stixmon_port = stixmon_port
    #    self.syslog_port = syslog_port

    def handle(self):
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]

        if LOG_FILE != '':
            logging.info(str(data))

        # Convert and Send to STIX Monitor
        send_observable_data(str(data), str(self.client_address[0]), stixmon_ip, stixmon_port, syslog_port)


def argparse_add_options(arg_parser):
    """Adds options to ArgumentParser"""
    arg_parser.add_argument('syslog_address_port', metavar='SYS_ADDR:PORT', help='Syslog IP Address:Port')
    arg_parser.add_argument('stixmon_ip_port', metavar='STIXMON_IP:PORT', help='STIX Monitor IP Address:Port')
    arg_parser.add_argument('--version', action='version',
                            version='%(prog)s {version}'.format(version=__version__))
    arg_parser.description = 'This is the SyslogEngine script.'


def send_observable_data(SYSLOG_MESSAGE, SRC_IP, stixmon_ip, stixmon_port, syslog_port):
    """Sends STIX object data to STIX Monitor"""
    STIX_TIME = datetime.datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    # Cleanup SyslogMessage
    SYSLOG_MESSAGE = SYSLOG_MESSAGE.rstrip('\x00')

    obs = {
        'created': STIX_TIME,
        'device_ref': 'device--71b4d7d9-daf1-4ae0-9027-706c3d88d4af',
        'first_observed': STIX_TIME,
        'id': 'observed-data--' + generateUUID(),
        'last_observed': STIX_TIME,
        'modified': STIX_TIME,
        'number_observed': 1,
        'objects': {'0': {'type': 'ipv4-addr', 'value': SRC_IP},
                    '1': {'type': 'ipv4-addr', 'value': stixmon_ip},
                    '2': {'mime_type': 'text/plain',
                          'payload': SYSLOG_MESSAGE,
                          'type': 'artifact'},
                    '3': {'src_ref': '0',
                          'dst_ref': '1',
                          'src_payload_ref': '2',
                          'src_port': syslog_port,
                          'dst_port': stixmon_port,
                          'protocols': ['tcp'],
                          'type': 'network-traffic'}},
        'type': 'observed-data'
    }

    if SEND_MODE == True:
        print(obs)
        print(json.dumps(obs, indent=4, sort_keys=True))
        res = requests.post('https://' + stixmon_ip + ":" + stixmon_port + '/api/stix-object/',
                            data=json.dumps(obs, indent=4, sort_keys=True), verify=False,
                            headers={'content-type': 'application/json'})
        print(res)
        print('Sent to STIX Monitor\n')

    if DISPLAY_MODE == True:
        print("%s : " % SRC_IP, SYSLOG_MESSAGE)
        print("\n" + str(obs) + "\n\n")

    return


def validateInput(syslog_ip, syslog_port, stixmon_ip, stixmon_port):
    """Validate input parameters"""
    # Make sure syslog_ip is in fact an IP address
    try:
        socket.inet_aton(syslog_ip)
    except socket.error:
        # Not legal
        raise Exception("SYSLOG IP must be a valid IP address")

    # Make sure syslog_port is an integer
    try:
        int(syslog_port)
    except ValueError:
        raise Exception("SYSLOG port must be an integer")

    # Make sure stixmon_ip is in fact an IP address
    try:
        socket.inet_aton(stixmon_ip)
    except socket.error:
        # Not legal
        raise Exception("STIXMON IP must be a valid IP address")

    # Make sure stixmon_port is an integer
    try:
        int(stixmon_port)
    except ValueError:
        raise Exception("STIXMON port must be an integer")


if __name__ == "__main__":

    # Make sure Python version is 3.5.x or greater
    if sys.version_info.major != 3:
        raise Exception("Must be using Python 3")
    if sys.version_info.minor < 5:
        raise Exception("Must be using Python 3 version 3.5.x or greater")

    arg_parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent('''\
                example:
                    python3 NetworkEngine.py 172.16.xxx.xxx/24 172.16.xxx.xxx:443
                '''))
    argparse_add_options(arg_parser)
    args = arg_parser.parse_args()

    syslog_address = args.syslog_address_port
    stix_monitor_address = args.stixmon_ip_port
    syslog_ip, syslog_port = syslog_address.split(':')[0], syslog_address.split(':')[1]
    stixmon_ip, stixmon_port = stix_monitor_address.split(':')[0], stix_monitor_address.split(':')[1]

    validateInput(syslog_ip, syslog_port, stixmon_ip, stixmon_port)

    try:
        print('Listening for UDP Syslogs sent to ' + syslog_address + ' (This Device)')
        #server = socketserver.UDPServer((syslog_ip, int(syslog_port)), SyslogUDPHandler(stixmon_ip, stixmon_port, syslog_port))
        server = socketserver.UDPServer((syslog_ip, int(syslog_port)), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print("Crtl+C Pressed. Shutting down.")
