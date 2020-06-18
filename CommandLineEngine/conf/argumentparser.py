"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""
import argparse
import textwrap

def argparse_add_options(arg_parser):
    """Adds options to ArgumentParser"""
    arg_parser.add_argument('sys_ip', metavar='IP', help='Target Device IP Address')
    arg_parser.add_argument('stixmon_ip_port', metavar='STIXMON_IP:PORT', help='STIX Monitor IP Address:Port')
    arg_parser.add_argument('mode', metavar='MODE', type = str.lower, help='Type of detction mode. Example: process, history')
    arg_parser.add_argument('-S', dest='stream', action='store_true', help='turn on stream mode for faster process polling')
    arg_parser.add_argument('-F', dest='filter', help='Filter pattern.')
    arg_parser.add_argument('-d', dest='delay', default=0, type=float, help='Check Rate in seconds (float). Default is 0.')
    arg_parser.add_argument('-P', dest='port', type=int, help='Port to be used for the connection, default is determined by CON_TYPE. Example: 22, 23, etc.')
    arg_parser.add_argument('-u', dest='username', type=str, help='Username for device, if required.')
    arg_parser.add_argument('-p', dest='password', type=str, help='Password for device, if required.')


def _validate_ip(ip):
    ip = ip.split('.')

    if len(ip) != 4:
        return False

    for item in ip:
        try:
            item = int(item)
        except ValueError:
            return False
        if item > 255 or item < 0:
            return False
    return True

def _validate_port(port):
    try:
        port = int(port)
    except ValueError:
        return False
    if port > 65535 or port < 0:
        return False
    return True

def _validate_delay(delay):
    try:
        delay = float(delay)
    except ValueError:
        return False
    if port < 0 or port > 86400:
        return False
    return True

def argparse_validate_arguments(args):
    """Validate passed in arguments"""
    if not _validate_ip(args.sys_ip):
        raise Exception('sys_ip must be valid IP address')

    if not _validate_ip(args.stixmon_ip_port.split(':')[0]):
        raise Exception('STIXMON_ADDRESS IP must be a valid IP')

    if not _validate_port(args.stixmon_ip_port.split(':')[1]):
        raise Exception('STIXMON_ADDRESS port must be a valid port')

    if args.mode != 'process' and args.mode != 'history':
        raise Exception('MODE must be "process" or "history"')

    if not _validate_delay:
        raise Exception('delay must be a positive float between 0-86400')

    if args.port is None:
        args.port = 22

    if not _validate_port(args.port):
        raise Exception('System port must be a valid port')

def argparse_get_options():
    arg_parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent('''\
                example:
                    python3 CommandLineEngine.py 172.16.xxx.xxx/24 172.16.xxx.xxx:443 <MODE ie: process> -u <user> -p <password> -F <process_name>
                '''))
    argparse_add_options(arg_parser)
    args = arg_parser.parse_args()
    argparse_validate_arguments(args)
    return args
