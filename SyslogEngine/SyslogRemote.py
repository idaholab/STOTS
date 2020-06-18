"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

__version__ = '1.0.0'

import argparse
import os
import socket
import sys
import urllib3
import textwrap

urllib3.disable_warnings()


#TODO: Make sure logic works here, added in while True
def start_filebeat_forwarder(filebeat_forwarder_address, password):
    """Starts Filebeat forwarder remotely"""
    while True:
        try:
            print('Sending Filebeat Entries to ' + filebeat_forwarder_address)
            if sys.platform == 'win32' or sys.platform == 'linux2':
                os.system(
                    'ncat -u ' + filebeat_forwarder_address.split(':')[0] + ' ' + filebeat_forwarder_address.split(':')[
                        1] + ' -e filebeat')
            else:
                os.system(
                    'echo ' + password + ' | sudo -S filebeat | nc -u ' + filebeat_forwarder_address.split(':')[0] + ' ' +
                    filebeat_forwarder_address.split(':')[1])
        except KeyboardInterrupt:
            print("Crtl+C Pressed. Shutting down.")


def argparse_add_options(arg_parser):
    """Adds options to ArgumentParser"""
    arg_parser.add_argument('filebeat_address_port', metavar='FILEBEAT_ADDR:PORT',
                            help='Filebeat Forwarder IP Address:Port')
    arg_parser.add_argument('-p', dest='password', help='Root Password for filebeat forwarder, if required.')
    arg_parser.add_argument('--version', action='version',
                            version='%(prog)s {version}'.format(version=__version__))
    arg_parser.description = 'This is the SyslogRemote script. This should be running along with filebeat on each remote machine.'


def validateInput(filebeat_forwarder_address):
    """Validate input parameters"""

    if filebeat_forwarder_address:
        # Make sure filebeat_forwarder_address is in fact an IP address
        try:
            socket.inet_aton(filebeat_forwarder_address.split(':')[0])
        except socket.error:
            # Not legal
            raise Exception("FILEBEAT Address must be valid IP address")

        # Make sure port of filebeat_forwarder_address is an integer
        try:
            int(filebeat_forwarder_address.split(':')[1])
        except ValueError:
            raise Exception("FILEBEAT port must be an integer")


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
                    python3 SyslogRemote.py 172.16.xxx.xxx/24 -p <password>
                '''))
    argparse_add_options(arg_parser)
    args = arg_parser.parse_args()

    filebeat_forwarder_address = args.filebeat_address_port

    validateInput(filebeat_forwarder_address)

    passw = ''
    if(args.password):
        passw = args.password

    if args.filebeat_address_port:
        start_filebeat_forwarder(filebeat_forwarder_address, args.password)
