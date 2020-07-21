#!/usr/bin/env python

import sys
import argparse
import configparser
import logging as log

from lib.helpers import CarbonBlack

log.basicConfig(filename='app.log', format='[%(asctime)s] <pid:%(process)d> %(message)s', level=log.DEBUG)
log.info('Sarted action script')


def init():
    log.debug('Initializing script')

    # Get configs
    log.debug('Getting configs')
    config = configparser.ConfigParser()
    config.read('config.conf')
    log.debug('Finished getting configs')

    # Get inputs
    log.debug('Getting cli inputs')
    parser = argparse.ArgumentParser(description='Take action on an endpoint via LiveResponse')
    parser.add_argument("--device_id", help='Log activity to a file', required=True)
    parser.add_argument('--command', help='Command to send to the endpoint', required=True)
    parser.add_argument('--argument', help='Argument to suppor the command being sent', default=None)
    parser.add_argument('--close', action='store_true', help='Close the session when script completes')
    args = parser.parse_args()
    log.debug('Finished cli inputs')

    # Init CarbonBlack
    cb = CarbonBlack(config, log)

    return cb, args


def main():
    cb, args = init()

    device_id = int(args.device_id)
    command = args.command
    process_id = args.argument

    cb.start_session(device_id, wait=True)

    log.debug('[Main] Connected to endpoint: {0}'.format(device_id))

    # Check to see if the process is still running
    lr_command = cb.send_command('process list', wait=True)

    for process in lr_command['processes']:
        if str(process['pid']) == process_id:
            # Send kill command
            lr_command = cb.send_command(command, argument=process_id, wait=True)

            log.debug('[Main] Command sent to endpoint')

            if args.close:
                cb.close_session()
                log.debug('[Main] Closed session')

            return 0

    log.warning('[Main] Process {0} was not running on device {1}'.format(process_id, device_id))
    return 1


if __name__ == "__main__":
    sys.exit(main())
