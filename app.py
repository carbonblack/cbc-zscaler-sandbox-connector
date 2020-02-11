import configparser
import argparse
import subprocess
import logging as log
import json
import os


# Import helpers
from lib.helpers import *

# Globals
config = None
db = None
cb = None
zs = None


def init():
    '''
        Initialze all of the objects for use in the integration

        Inputs: None

        Outputs:
            config: A dictionary of the settings loaded from config.ini
            db: An object with everything needed for this script to work with sqlite3
            cb: An object with everything needed for this script to work with CarbonBlack Cloud
            zs: An object with everything needed for this script to work with Zscaler ZIA Sandbox
    '''

    global config, db, cb, zs

    # Configure logging
    log.basicConfig(filename='app.log', format='[%(asctime)s] <pid:%(process)d> %(message)s', level=log.DEBUG)
    log.info('[APP.PY] Sarted <!!!name of integration here...!!!>')

    # Get setting from config.ini
    config = configparser.ConfigParser()
    config.read('config.conf')

    # Configure CLI input arguments
    parser = argparse.ArgumentParser(description='Description of the app here...')
    parser.add_argument('--last_pull', help='Set the last pull time in ISO8601 format')
    args = parser.parse_args()

    # Init database
    db = Database(config, log)

    if args.last_pull:
        db.last_pull(args.last_pull)

    # Init CarbonBlack
    cb = CarbonBlack(config, log)

    # Init Zscaler
    zs = Zscaler(config, log)

    return config, db, cb, zs

def take_action(cb_event, zs_report):
    # Populate actions with either None or the action defined
    actions = {}
    for action in config['actions']:
        if config['actions'][action] == '':
            actions[action] = None
        else:
            actions[action] = config['actions'][action]

    # Create/update watchlist feed
    if actions['watchlist'] != None:
        report = cb.create_report(
            zs_report['timestamp'],
            zs_report['title'],
            zs_report['description'],
            zs_report['severity'],
            zs_report['link'],
            zs_report['tags'],
            zs_report['md5']
        )

        feed = cb.get_feed(feed_name=watchlist)
        if feed == None:
            feed = cb.create_feed(
                watchlist,
                config['Zscaler']['url'],
                'Found Reports from Zscaler ZIA Sandbox',
                report
            )
        else:
            update_feed(feed, report)

    # Send data to webhook
    if actions['webhook'] != None:
        url = actions['webhook']
        headers = {
            'Content-Type': 'application/json'
        }
        body = {
            'cb_event': cb_event,
            'zs_report': zs_report
        }
        r = requests.post(url, headers=headers, json=body)

    # Run a script
    if actions['script'] != None:
        log.info('[APP.PY] Running Script')
        device_id = str(cb_event['device_id'])
        process_id = str(cb_event['pid'])
        script_cwd = os.path.dirname(os.path.realpath(__file__))
        stdin = stdout = subprocess.PIPE

        script = config['actions']['script']
        script = script.replace('{device_id}', device_id)
        script = script.replace('{command}', 'kill')
        script = script.replace('{argument}', process_id)
        script = script.split(' ')

        cmd = [os.path.join(script_cwd, script[0])]
        args = script[1:]

        log.info('[APP.PY] {0} {0}'.format(cmd, args))

        sub_script = subprocess.Popen(cmd + args, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        log.info('[APP.PY] this comes after the subprocess')

    # !!! Isolate endpoint
    if actions['isolate'].lower() in ['true', '1']:
        cb.isolate_device(event['device_id'])

    if actions['policy'] != None:
        cb.update_policy(event['device_id'], actions['policy'])


def process_events(events):
    for event in events:

        # for testing CBD hash issues
        if 'eventId' in event:
            log.debug('[!!!] Event: {0}'.format(json.dumps(event, indent=4)))
            log.debug('[!!!] EventID: {0}'.format(event['eventId']))
            log.debug('[!!!] MD5: {0}'.format(event['md5']))
            log.debug('[!!!] SHA256: {0}'.format(event['sha256']))

        # Check to see if we know about this file in the database
        db_record = db.get_file(md5=event['md5'])

        # If we don't know about it
        if db_record is None:
            # Check to see if Zscaler knows about the file
            zs_report = zs.get_report(event['md5'])

            # If Zscaler does know about it
            if zs_report not in [None, False]:
                zs_type = zs_report['Summary']['Classification']['Type']
                # Add the file to the database
                db.add_file(md5=event['md5'], sha256=event['sha256'], status=zs_type)

                # If Zscaler says it is bad
                if zs_type in zs.bad_types:
                    take_action(event, zs_report)

            elif zs_report is None:
                db.add_file(md5=event['md5'], sha256=event['sha256'], status='UNKNOWN')

        # If we do know about the file
        else:
            timestamp = db_record[0][1]
            status = db_record[0][4]
            now = datetime.strptime(convert_time('now'), '%Y-%m-%dT%H:%M:%S.%fZ')
            date_added = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
            difference = now - date_added
            hours = difference.seconds / 60 / 60
            days = hours / 24

            # If the last report is more than 30 days old, check again
            if days >= 30:
                zs_report = zs.get_report(event['md5'])
                db.update_file(event['md5'])

            if status in zs.bad_types:
                # Only take 1 action every 3 hours
                if hours > 3:
                    take_action(event, zs_report)
    return


def main():
    # Get inits
    init()

    cbth_enabled = str2bool(config['CarbonBlack']['cbth_enabled'])
    cbd_enabled = str2bool(config['CarbonBlack']['cbd_enabled'])

    if cbth_enabled:
        # Get the start and end times
        # Start time comes from the datbase's last_pull time
        start_time = db.last_pull()

        # End time is the 'upper' of available span
        available_span = cb.get_available_span()
        end_time = convert_time(available_span['upper'])

        # Build the query based on start/end_time and process reputation from configs
        query = 'process_start_time:[{0} TO {1}] AND process_reputation:'.format(start_time, end_time)
        q_filters = config['CarbonBlack']['filters'].split(',')
        q_filters2 = ' AND process_effective_reputation:'.join(q_filters)
        query = '{0}{1}'.format(query, q_filters2)

        # Submit the query and get a list of processes unique by hash
        events = cb.get_processes(query, db)

        # Process events
        process_events(events)

        # Update the last pull time
        db.last_pull(timestamp=convert_time(end_time))

    if cbd_enabled:
        # Get unique CBD events for the last 3h
        events = cb.get_events(timespan='3h')

        # Process events
        process_events(events)

    db.close()


if __name__ == '__main__':
    main()