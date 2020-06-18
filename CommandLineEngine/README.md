# Structured Threat Observable Tool Set (STOTS)

## Introduction

STOTS allow users to capture and send STIX v2 observed data objects in lieu of other tools.

More information on STIX can be found here: https://oasis-open.github.io/cti-documentation/stix/intro.
### Command Line Engine
Command Line Engine (CLE) is a command line interface (CLI) program written to monitor commands executed on the command line (or on the shell) of a given system. To do this Command Line Engine remotes into devices using SSH and either executes the 'ps' command to see currently running processes and their arguments, or reads the bash history for one or more users. The commands are processed into a unique set and compared against the previous set, differences are sent to the configured TMA as a formatted JSON observed data object payload. Currently Commandline engine only supports Linux/Unix sysystems.

### Usage

python3 CommandLineEngine.py [-h] [-S] [-F FILTER] [-d DELAY] [-p PORT] [-u USERNAME] [-P PASSWORD] IP STIXMON_IP:PORT MODE

The following arguments are required: IP, STIXMON_IP:PORT, MODE

IP - The IP address o the system to monitor.

STIXMON_IP:PORT - The IP and port of the system that observed data objects will be sent to.

MODE - Whether the engine will use the process listing or bash history for monitoring, must be 'history' or 'process'

Additional optional arguments:

-S Turns on stream mode for constant, faster polling when using the 'process' mode, takes no arguments

-F Takes a filter string, only commands containing the filter string will be registered

-d Takes a positive float between 0 and 86400, this will be used as a delay between checks

-u Username for the device to be monitored

-p Password for the device to be monitored

-P Port that will be used for ssh, defaults to 22

#### Dependencies

Command Line Engine requires several Python3 modules, all of which can be installed with pip/pip3.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Licensing

See COPYRIGHT.txt and LICENSE.txt for copyright and licensing information.
