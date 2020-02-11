#!/usr/bin/env python

import sys
import argparse
import configparser
import logging as log
from time import sleep

from lib.helpers import CarbonBlack
from cbapi.psc.defense import CbDefenseAPI, Device

log.basicConfig(filename='app.log', format='[%(asctime)s] <pid:%(process)d> %(message)s', level=log.DEBUG)
log.info('Sarted action script')

def connect_callback(cb, line):
    try:
        sensor_id = int(line)
    except ValueError:
        sensor_id = None

    if not sensor_id:
        q = cb.select(Device).where("hostNameExact:{0}".format(line))
        sensor = q.first()
    else:
        sensor = cb.select(Device, sensor_id)

    return sensor


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

    '''
        !!! check to see if process is still running
    '''

    lr_session = cb.start_session(int(args.device_id))

    # Check every 15 seconds for the status of the connection
    while lr_session['status'] == 'PENDING':
        sleep(15)
        lr_session = cb.get_session()

    print('[Main] Connected to endpoint: {0}'.format(args.device_id))

    lr_command = cb.send_command(args.command, argument=args.argument)

    # Check every 5 seconds for the status of the command
    while lr_command['status'] == 'pending':
        sleep(5)
        lr_command = cb.command_status(lr_command['id'])

    if lr_command['status'] == 'BAD_REQUEST':
        sys.exit(1)

    print('[Main] Command sent to endpoint')

    if args.close:
        cb.close_session()
        print('[Main] Closed session')

if __name__ == "__main__":
    sys.exit(main())