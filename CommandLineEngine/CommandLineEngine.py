"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

import sys
import json
import requests
import threading
from time import sleep
from datetime import datetime
from uuid import uuid4
import urllib3

from conf.ssh import SSH
from conf.argumentparser import argparse_get_options
from conf.history import history

urllib3.disable_warnings()


# conforms to RFC-4122
def generateUUID():
    return str(uuid4())

def sendObsData(sysIP, obsList, stixmon_ip, stixmon_port):
    """Sends STIX object data to STIX Monitor"""

    STIX_TIME = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    obsString = ''
    for item in obsList:
        obsString += item + '\n'
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
                    '1': {'type': 'ipv4-addr', 'value': stixmon_ip},
                    '2': {'mime_type': 'text/plain',
                          'payload': 'CommandLineEngine: ' + obsString,
                          'type': 'artifact'},
                    '3': {'src_ref': '0',
                          'dst_ref': '1',
                          'src_payload_ref': '2',
                          'src_port': 6666,
                          'dst_port': stixmon_port,
                          'protocols': ['tcp'],
                          'type': 'network-traffic'}},
        'type': 'observed-data'
    }

    print(json.dumps(obs, indent=4, sort_keys=True))
    res = requests.post('https://' + stixmon_ip + ":" + stixmon_port + '/api/stix-object/',
                        data=json.dumps(obs, indent=4, sort_keys=True), verify=False,
                        headers={'content-type': 'application/json'})
    if res.status_code == 201:
        print('Sent to STIX Monitor\n')
    else:
        print('Error! Invalid status code returned from Stix Monitor\n', res.text)
    return


if __name__ == "__main__":

    # Make sure Python version is 3.5.x or greater
    if sys.version_info.major != 3:
        raise Exception('Must be using Python 3')
    if sys.version_info.minor < 5:
        raise Exception('Must be using Python 3 version 3.5.x or greater')

    args = argparse_get_options()

    host = args.sys_ip
    stixmon_ip = args.stixmon_ip_port.split(':')[0]
    stixmon_port = args.stixmon_ip_port.split(':')[1]
    mode = args.mode
    delay = args.delay
    port = args.port
    username = args.username
    password = args.password
    stream_flag = args.stream

    con = SSH(host, port, username, password)
    hist = history()

    if mode == 'history':
        curUser = con.exec('whoami').rstrip('\n')
        users = []
        if curUser == 'root':
            for item in con.exec('ls /home -1').splitlines():
                users.append((item, history()))
        while True:
            for user in users:
                history_text = con.exec('cat /home/' + user[0] + '/.bash_history')
                results = user[1].compare(history_text)
                if len(results) > 0:
                    #Remove invalid character
                    results = [ x for x in results if "\x00" not in x ]
                    threading.Thread(target=sendObsData, args=(host, results, stixmon_ip, stixmon_port)).start()
            history_text = con.exec('cat .bash_history')
            results = hist.compare(history_text)
            if len(results) > 0:
                #Remove invalid character
                results = [ x for x in results if "\x00" not in x ]
                threading.Thread(target=sendObsData, args=(host, results, stixmon_ip, stixmon_port)).start()
            sleep(delay)

    if mode == 'process':
        if stream_flag:
            con.get_stream('while true\n do\n ps -eo args\n done')
            once = True
            line = ''
            while True:
                line += con.get_stream_data(1024).decode()
                if 'COMMAND\n' in line:
                    line = line.split('COMMAND\n')
                    if (once):
                        line.pop(0)
                        once = False
                    while len(line) > 1:
                        results = hist.compare(line.pop(0))
                        if len(results) > 0:
                            threading.Thread(target=sendObsData, args=(host, results, stixmon_ip, stixmon_port)).start()
                    line = line[0]
        else:
            while True:
                history_text = con.exec('ps -eo args')
                results = hist.compare(history_text)
                if len(results) > 0:
                    threading.Thread(target=sendObsData, args=(host, results, stixmon_ip, stixmon_port)).start()
                sleep(delay)
