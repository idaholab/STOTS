"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

__version__ = '1.0.0'

import os.path
import datetime
import requests
import time
import uuid
import urllib3
import json
import nmap
import sys
import argparse
import socket
import textwrap

urllib3.disable_warnings()


def generateUUID():
    return str(uuid.uuid4())


def argparse_add_options(arg_parser):
    """Adds options to ArgumentParser"""
    arg_parser.add_argument('network_ip_cidr', metavar='CIDR_IP', help='CIDR IP Address/Subnet. Example: 192.168.1.0/24')
    arg_parser.add_argument('stixmon_ip_port', metavar='STIXMON_IP:PORT', help='STIX Monitor IP Address:Port')
    arg_parser.add_argument('-d', dest='delay', default=60, type=int,
                            help='Check Rate/Delay in seconds. Default is 60.')
    arg_parser.add_argument('--version', action='version',
                            version='%(prog)s {version}'.format(version=__version__))
    arg_parser.description = 'This is the NetworkEngine script.'


def obtainConfig(networkIP):
    """Scans network to get a list of hosts"""
    print('     Scanning...')
    nm = nmap.PortScanner()
    hosts_list = nm.scan(hosts=networkIP, arguments='-T5 --min-parallelism=50 -sP')
    hosts_set = set(nm.all_hosts())
    output = ''
    for i in hosts_set:
        output += i + '\n'
    return output


def sendObsData(networkIP, obsString, stix_monitor_address):
    """Sends STIX object data to STIX Monitor"""
    print('     Sending...')
    STIX_TIME = datetime.datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    # Cleanup obsString
    obsString = obsString.rstrip('\x00')

    obs = {
        'created': STIX_TIME,
        'device_ref': 'device--71b4d7d9-daf1-4ae0-9027-706c3d88d4af',
        'first_observed': STIX_TIME,
        'id': 'observed-data--' + generateUUID(),
        'last_observed': STIX_TIME,
        'modified': STIX_TIME,
        'number_observed': 1,
        'objects': {'0': {'type': 'ipv4-addr', 'value': networkIP.split('/')[0]},
                    '1': {'type': 'ipv4-addr', 'value': stix_monitor_address.split(':')[0]},
                    '2': {'mime_type': 'text/plain',
                          'payload': 'NetworkEngine: ' + obsString,
                          'type': 'artifact'},
                    '3': {'src_ref': '0',
                          'dst_ref': '1',
                          'src_payload_ref': '2',
                          'src_port': 6666,
                          'dst_port': stix_monitor_address.split(':')[1],
                          'protocols': ['tcp'],
                          'type': 'network-traffic'}},
        'type': 'observed-data'
    }

    print(json.dumps(obs, indent=4, sort_keys=True))
    res = requests.post('https://' + stix_monitor_address.split(':')[0] + ":" + stix_monitor_address.split(':')[
        1] + '/api/stix-object/', data=json.dumps(obs, indent=4, sort_keys=True), verify=False,
                        headers={'content-type': 'application/json'})
    return


def validateInput(networkIP, stix_monitor_address):
    """Validate input parameters"""
    # Make sure networkIP is in fact an IP address
    try:
        socket.inet_aton(networkIP.split('/')[0])
    except socket.error:
        # Not legal
        raise Exception("CIDR must contain a valid IP address")

    # Make sure networkIP CIDR notation is valid
    if int(networkIP.split('/')[1]) > 32:
        raise Exception("CIDR notation for IPv4 should be a number between 0-32")

    # Make sure stix_monitor_address is in fact an IP address
    try:
        socket.inet_aton(stix_monitor_address.split(':')[0])
    except socket.error:
        # Not legal
        raise Exception("STIXMON_ADDRESS must be valid IP address")

    # Make sure port to STIX Monitor is an integer
    try:
        int(stix_monitor_address.split(':')[1])
    except ValueError:
        raise Exception("STIXMON_ADDRESS port must be an integer")


if __name__ == '__main__':

    # Make sure Python version is 3.5.x or greater
    if sys.version_info.major != 3:
        raise Exception("Must be using Python 3")
    if sys.version_info.minor < 5:
        raise Exception("Must be using Python 3 version 3.5.x or greater")

    arg_parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent('''\
                example:
                    python3 NetworkEngine.py 172.16.xxx.xxx/24 172.16.xxx.xxx:443 -d 5
                '''))
    argparse_add_options(arg_parser)
    args = arg_parser.parse_args()

    networkIP = args.network_ip_cidr
    stix_monitor_address = args.stixmon_ip_port
    delay = args.delay

    validateInput(networkIP, stix_monitor_address)

    # Loop Forever
    while True:
        prev = ''
        prevConfig = networkIP.split('/')[0].replace('.', '_') + '-prev.log'

        if not os.path.isfile(prevConfig):
            print('Previous Device List Not Found.')
            print('Collecting Initial Device List')
            f = open(prevConfig, 'w')
            prev = obtainConfig(networkIP)
            f.write(prev)
            f.close()
        else:
            f = open(prevConfig, 'r')
            prev = f.read()
            f.close()

        curr = obtainConfig(networkIP)

        # Replace prevConfig with currConfig
        os.remove(prevConfig)
        f = open(prevConfig, 'w')
        f.write(curr)
        f.close()

        # Convert StringList to Sets
        currSet = set(curr.splitlines())
        prevSet = set(prev.splitlines())

        diff_curr_vs_prev = currSet.difference(prevSet)
        diff_prev_vs_curr = prevSet.difference(currSet)

        results = ''
        for x in diff_curr_vs_prev:
            results += '+ ' + x + '\n'
        for x in diff_prev_vs_curr:
            results += '- ' + x + '\n'

        if results != '':
            print('Sending...')
            sendObsData(networkIP, results, stix_monitor_address)
        else:
            print('No Changes Detected')

        # Pause between checks
        print('     Waiting...')
        time.sleep(delay)
