"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""
__version__ = '1.0.0'

import datetime
import json
import os.path
import platform
import requests
import subprocess
import sys
import time
import urllib3
import uuid
import argparse
import socket
import paramiko
import textwrap

urllib3.disable_warnings()

def obtainList(path, dest_ip, username, password):
    """Obtains a directory list depending on architecture"""
    print('     Obtaining Tree...')

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(dest_ip, username=username, password=password)

    if (targetOS == 'Windows'):
        stdin, stdout, stderr = ssh.exec_command("dir " + path)
        checkResult = stdout.read()
        output = '\n'.join(checkResult.decode('utf-8').split('\n')[7:-3])
    else:  # Linux
        stdin, stdout, stderr = ssh.exec_command('ls -la ' + path)
        checkResult = stdout.read()
        output = '\n'.join(checkResult.decode('utf-8').split('\n')[3:])

    return output


def argparse_add_options(arg_parser):
    """Adds options to ArgumentParser"""
    arg_parser.add_argument('sys_ip', metavar='DEVICE_IP', help='Device IP Address')
    arg_parser.add_argument('stixmon_ip_port', metavar='STIXMON_IP:PORT', help='STIX Monitor IP Address:Port')
    arg_parser.add_argument('path', metavar='PATH', help='Destination path to monitor for files')
    arg_parser.add_argument('-d', dest='delay', default=2, type=int,
                            help='Check Rate/Delay in seconds. Default=2.')
    arg_parser.add_argument('-u', dest='username', help='Username for device, if required.')
    arg_parser.add_argument('-p', dest='password', help='Password for device, if required.')
    arg_parser.add_argument('--os', dest='targetOS', default='Linux', help='OS of Traget System. Default=Linux')
    arg_parser.add_argument('--version', action='version',
                            version='%(prog)s {version}'.format(version=__version__))
    arg_parser.description = 'This is the SyslogEngine scriptself.'


def sendObsData(path, obsString, stix_monitor_address):
    """Sends STIX object data to STIX Monitor"""
    print('     Sending...')
    STIX_TIME = datetime.datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    # Cleanup obsString
    obsString = obsString.rstrip('\x00')

    obs = {
        'created': STIX_TIME,
        'device_ref': 'device--71b4d7d9-daf1-4ae0-9027-706c3d88d4af',
        'first_observed': STIX_TIME,
        'id': 'observed-data--' + str(uuid.uuid4()),
        'last_observed': STIX_TIME,
        'modified': STIX_TIME,
        'number_observed': 1,
        'objects': {'0': {'type': 'ipv4-addr', 'value': path},
                    '1': {'type': 'ipv4-addr', 'value': stix_monitor_address.split(':')[0]},
                    '2': {'mime_type': 'text/plain',
                          'payload': 'FileEngine: ' + obsString,
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
    #if int(networkIP.split('/')[1]) > 33:
    #    raise Exception("CIDR notation for IPv4 should be a number between 0-32")

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
                    python3 NetworkEngine.py 172.16.xxx.xxx/24 172.16.xxx.xxx:443 -z <absolute_path_to_directory> -u <user> -p <password> --os Linux
                '''))
    argparse_add_options(arg_parser)
    args = arg_parser.parse_args()

    networkIP = args.sys_ip
    stix_monitor_address = args.stixmon_ip_port
    delay = args.delay
    path = args.path
    targetOS = args.targetOS

    validateInput(networkIP, stix_monitor_address)

    # Loop Forever
    while True:
        prev = ''
        prevList = 'FileEngine-prev.log'

        if not os.path.isfile(prevList):
            print('Previous File List Not Found.')
            print('Collecting Initial File List')
            f = open(prevList, 'w')
            prev = obtainList(path, networkIP, args.username, args.password)
            f.write(prev)
            f.close()
        else:
            f = open(prevList, 'r')
            prev = f.read()
            f.close()

        curr = obtainList(path, networkIP, args.username, args.password)

        # Replace prevList with currList
        os.remove(prevList)
        f = open(prevList, 'w')
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
            sendObsData(path, results, stix_monitor_address)
        else:
            print('No Changes Detected')

        # Pause between checks
        print('     Waiting...')
        time.sleep(delay)
