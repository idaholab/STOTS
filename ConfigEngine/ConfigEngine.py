"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

"""
Custom scripts/functions will need to be written to meet individual user and device needs.
The only requirement for a custom script to obtain a device configuration is that the
obtained config must be returned as a text string. See code comments.
"""
__version__ = '1.0.0'

import difflib
import os.path
import datetime
import requests
import time
import uuid
import urllib3
import json
import telnetlib
import sys
import argparse
import socket
import paramiko
import textwrap

urllib3.disable_warnings()


def generateUUID():
    return str(uuid.uuid4())

def argparse_add_options(arg_parser):
    """Adds options to ArgumentParser"""
    arg_parser.add_argument('sys_ip', metavar='DEVICE_IP', help='Device IP Address')
    arg_parser.add_argument('stixmon_ip_port', metavar='STIXMON_IP:PORT', help='STIX Monitor IP Address:Port')
    arg_parser.add_argument('device_select', metavar='DEVICE',
                            help='Device type.')
    arg_parser.add_argument('-d', dest='delay', default=60, type=int,
                            help='Check Rate/Delay in seconds. Default is 60.')
    arg_parser.add_argument('-u', dest='username', help='Username for device, if required.')
    arg_parser.add_argument('-p', dest='password', help='Password for device, if required.')
    arg_parser.add_argument('--version', action='version',
                            version='%(prog)s {version}'.format(version=__version__))
    arg_parser.description = 'This is the ConfigEngine script.'


def obtainConfig(sysIP_device, uname=None, pwd=None):
    """Obtains configurations for specific devices.  If device is not supported, exits script"""
    if sysIP_device == 'GENERIC':   # add name of device here
        result = obtainGENERICConfig(sysIP, pwd)
    elif sysIP_device == 'GENERIC2':   # add name of device here
        result = obtainGENERIC2Config(sysIP, uname, pwd)
    else:
        print('Unknown Device')
        sys.exit()
    return result

def obtainGENERICConfig(sysIP, uname, pwd):     # device specific configuration scripts, ref line 47
    """Obtain configuration for GENERIC device"""
    """
       Insert script to collect and output device config as a string

       Example telnet:
       tn = telnetlib.Telnet(sysIP, 23, 5)
       tn.write(("\r\n").encode('ascii'))
       response = tn.read_until((">").encode('ascii'), 3)
       ...
       ...
       ...
    """
    return cmdOutput.decode()

def obtainGENERIC2Config(sysIP, uname, pwd):        # device specific configuration scripts, ref line 49
    """Obtain configuration for additional GENERIC device"""
    """
       Insert script to collect and output device config as a string

       Example ssh:
       ssh = paramiko.SSHClient()
       ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
       ssh.connect(sysIP, username=uname, password=pwd, look_for_keys=False, allow_agent=False)
       ssh2 = ssh.invoke_shell()
       output = ssh2.recv(65535)
       ...
       ...
       ...
    """
    return cmdOutput.decode()

def sendObsData(sysIP, obsString, stix_monitor_address):
    """Sends STIX object data to STIX Monitor"""
    STIX_TIME = datetime.datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    # Cleanup obsString
    obsString = obsString.rstrip('\x00')

    print('    Sending...')

    obs = {
        'created': STIX_TIME,
        'device_ref': 'device--71b4d7d9-daf1-4ae0-9027-706c3d88d4af',
        'first_observed': STIX_TIME,
        'id': 'observed-data--' + generateUUID(),
        'last_observed': STIX_TIME,
        'modified': STIX_TIME,
        'number_observed': 1,
        'objects': {'0': {'type': 'ipv4-addr', 'value': sysIP},
                    '1': {'type': 'ipv4-addr', 'value': stix_monitor_address.split(':')[0]},
                    '2': {'mime_type': 'text/plain',
                          'payload': 'ConfigEngine: ' + obsString,
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
    print('Sent to STIX Monitor\n')
    return


def validateInput(sysIP, stix_monitor_address):
    """Validate input parameters"""
    # Make sure sysIP is in fact an IP address
    try:
        socket.inet_aton(sysIP)
    except socket.error:
        # Not legal
        raise Exception("IP must be valid IP address")

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
        raise Exception("STIXMON_ADDRESS port must be integer")


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
                    python3 NetworkEngine.py 172.16.xxx.xxx/24 172.16.xxx.xxx:443 <DEVICE ie: SEL> -u <user> -p <password> -d 5
                '''))

    argparse_add_options(arg_parser)
    args = arg_parser.parse_args()

    sysIP = args.sys_ip
    stix_monitor_address = args.stixmon_ip_port
    delay = args.delay
    sysIP_device = args.device_select

    validateInput(sysIP, stix_monitor_address)

    # Loop Forever
    while True:
        prev = ''
        prevConfig = sysIP.replace('.', '_') + '-prev.log'

        if not os.path.isfile(prevConfig):
            print('Previous Config File Not Found.')
            print('Collecting Initial Config')
            f = open(prevConfig, 'w')
            prev = obtainConfig(sysIP_device, args.username, args.password)
            f.write(prev)
            f.close()
        else:
            f = open(prevConfig, 'r')
            prev = f.read()
            f.close()

        print('    Checking...')

        message = 'Telnet Collision'
        curr = 'Blank'
        while curr == 'Blank':
            try:
                curr = obtainConfig(sysIP_device, args.username, args.password)
            except:
                print('    Collision...', end='\r')

        # Replace prevConfig with currConfig
        os.remove(prevConfig)
        f = open(prevConfig, 'w')
        f.write(curr)
        f.close()

        prevLines = prev.splitlines()
        currLines = curr.splitlines()

        diff = difflib.Differ().compare(prevLines, currLines)

        diff = '\n'.join(diff).split('\n')

        results = ''
        for x in range(1, len(diff)):
            if len(diff[x]) > 0:
                if diff[x][0] == '+' or diff[x][0] == '-':
                    results += diff[x] + '\n'

        if results != '':
            sendObsData(sysIP, results, stix_monitor_address)
        else:
            print('No Changes Detected')

        # Pause between checks
        print('    Waiting...')
        time.sleep(delay)
