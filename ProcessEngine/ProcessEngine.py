"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

__version__ = '1.0.0'

from datetime import datetime
import json
import requests
import time
import uuid
import sys
import subprocess
from subprocess import DEVNULL
import platform
import urllib3
import argparse
import socket
import paramiko
import textwrap

urllib3.disable_warnings()

# Store Start Time
startTime = time.time()

def argparse_add_options(arg_parser):
    """Adds options to ArgumentParser"""
    arg_parser.add_argument('sys_ip', metavar='DEVICE_IP', help='Device IP Address.')
    arg_parser.add_argument('stixmon_ip_port', metavar='STIXMON_IP:PORT', help='STIX Monitor IP Address:Port.')
    arg_parser.add_argument('-r', dest='runtime', default=0, type=int,
                            help='RunTime for running the Engine, a value of 0 or less will run continually.')  # TODO: DO we need to change the logic for runtime/checktime
    arg_parser.add_argument('-d', dest='checktime', default=5, type=int,
                            help='Check Rate/Delay in seconds. Default is 60.')
    arg_parser.add_argument('-u', dest='username', help='Username for device, if required.')
    arg_parser.add_argument('-p', dest='password', help='Password for device, if required.')
    arg_parser.add_argument('--os', dest='targetOS', default='Linux', help='OS of target device.')
    arg_parser.add_argument('-a', dest='absence_presence', default='p',
                            help='Check for (a)bsence or (p)resence of a file. Example: -a p')
    arg_parser.add_argument('process_list', action='store', type=str, nargs='+', metavar='PROCESS_LIST', help='A list of processes.')
    arg_parser.add_argument('--version', action='version',
                            version='%(prog)s {version}'.format(version=__version__))
    arg_parser.description = 'This is the ProcessEngine script.'


def validateInput(networkIP, stix_monitor_address):
    """Validate input parameters"""
    # Make sure networkIP is in fact an IP address
    try:
        socket.inet_aton(networkIP.split('/')[0])
    except socket.error:
        # Not legal
        raise Exception("DEVICE_IP must contain a valid IP address")

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
                    python3 NetworkEngine.py 172.16.xxx.xxx/24 172.16.xxx.xxx:443 -c 5 -r 60 -l ping -u <user> -p <password>
                '''))
    argparse_add_options(arg_parser)
    args = arg_parser.parse_args()

    networkIP = args.sys_ip
    stix_monitor_address = args.stixmon_ip_port
    checktime = args.checktime
    runtime = args.runtime
    abs_pres = args.absence_presence
    alist = args.process_list
    targetOS = args.targetOS

    validateInput(networkIP, stix_monitor_address)

    if abs_pres == 'a':
        print("Checking for absence of " + str(alist) + " every " + str(checktime) + " secs on " +
            str(networkIP) + ". Will Sending Observable Object to STIX Monitor @ " + str(stix_monitor_address))
    else:
        print("Checking for presence of " + str(alist) + " every " + str(checktime) + " secs on " +
            str(networkIP) + ". Will Sending Observable Object to STIX Monitor @ " + str(stix_monitor_address))

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(networkIP, username=args.username, password=args.password)

    while True:
        # Check if been running for full runtime
        if int(runtime) > 0:
            if time.time() - startTime > int(runtime):
                sys.exit()

        # Check if process running
        for process in alist:
            STIX_TIME = datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            if (targetOS == 'Windows'):
                stdin, stdout, stderr = ssh.exec_command("tasklist | findstr -i " + process)
                checkResult = stdout.read()
            else:  # Linux
                stdin, stdout, stderr = ssh.exec_command('pgrep -x ' + process)
                checkResult = stdout.read()

            if len(str(checkResult.decode())) != 0:
                returnCode = 0
            else:
                returnCode = 1

            if (returnCode != 1 and abs_pres == 'p') or (returnCode == 1 and abs_pres == 'a'):
                stix_time = datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

                if abs_pres == 'p':
                    obs = {
                          'created': STIX_TIME,
                          'device_ref': 'device--71b4d7d9-daf1-4ae0-9027-706c3d88d4af',
                          'first_observed': STIX_TIME,
                          'id': 'observed-data--' + str(uuid.uuid4()),
                          'last_observed': STIX_TIME,
                          'modified': STIX_TIME,
                          'number_observed': 1,
                          'objects': {'0': {'type': 'ipv4-addr', 'value': stix_monitor_address.split(':')[0]},
                              '1': {'mime_type': 'text/plain',
                                   'payload': 'ProcessEngine: ' + process + ' process is present',
                                   'type': 'artifact'},
                              '2': {'dst_ref': '0',
                                   'src_payload_ref': '1',
                                   'src_port': 6666,
                                   'dst_port': 443,
                                   'protocols': ['tcp'],
                                   'type': 'network-traffic'}},
                              'type': 'observed-data'
                          }
                else:
                    obs = {
                          'created': STIX_TIME,
                          'device_ref': 'device--71b4d7d9-daf1-4ae0-9027-706c3d88d4af',
                          'first_observed': STIX_TIME,
                          'id': 'observed-data--' + str(uuid.uuid4()),
                          'last_observed': STIX_TIME,
                          'modified': STIX_TIME,
                          'number_observed': 1,
                          'objects': {'0': {'type': 'ipv4-addr', 'value': stix_monitor_address.split(':')[0]},
                              '1': {'mime_type': 'text/plain',
                                   'payload': 'ProcessEngine: ' + process + ' process is NOT present',
                                   'type': 'artifact'},
                              '2': {'dst_ref': '0',
                                   'src_payload_ref': '1',
                                   'src_port': 6666,
                                   'dst_port': 443,
                                   'protocols': ['tcp'],
                                   'type': 'network-traffic'}},
                              'type': 'observed-data'
                          }

                print("Observable: \n%s" % obs)
                res = requests.post('https://' + stix_monitor_address + '/api/stix-object/', json.dumps(obs, indent=4, sort_keys=True), verify=False, headers={'content-type': 'application/json'})
                if res.status_code != 201:
                    raise RuntimeError('post request failed', res.status_code, res.text)

        # Pause before checking again
        time.sleep(int(checktime))
