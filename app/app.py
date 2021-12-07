# -*- coding: utf-8 -*-

import configparser
import argparse
import subprocess
import logging as log
import json
import os
import requests
from datetime import datetime

# Import helpers
from lib.helpers import CarbonBlack, Database, Zscaler, convert_time, str2bool, script_queue

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
            config: A dictionary of the settings loaded from config.conf
            db: An object with everything needed for this script to work with sqlite3
            cb: An object with everything needed for this script to work with CarbonBlack Cloud
            zs: An object with everything needed for this script to work with Zscaler ZIA Sandbox
    '''

    global config, db, cb, zs

    app_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(app_path, 'config.conf')
    if os.path.isfile(config_path) is False:
        raise Exception('\n\n[APP.PY] Unable to find config.conf in {0}'.format(app_path))

    # Get setting from config.ini
    config = configparser.ConfigParser()
    config.read(config_path)

    # Configure logging
    level = log.getLevelName(config['logging']['log_level'])
    log_path = os.path.join(app_path, config['logging']['filename'])
    log.basicConfig(filename=log_path, format='[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s', level=level)

    log.info('\n\n[APP.PY] Sarted Zscaler ZIA Sandbox Connector for VMware Carbon Black Cloud')

    # Configure CLI input arguments
    parser = argparse.ArgumentParser(description='Get events / processes from VMware Carbon Black Cloud')
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
    '''
        Takes action on endpoints and processes with hashes that returned malicious results from
          Zscaler's sandbox.

        Inputs:
            cb_event: The processes that was identified to have the malicious hash
            zs_report: The report of the hash from Zscaler's sandbox
        
        Outputs:
            The actions are enabled or disabled in the config file.
            watchlist: Adds the hash to a watchlist
            webhook: Triggers a HTTP POST to a URL with the process, report and hash
            script: Executes a script
            isolate: Isolates the endpoint
            policy: Changes the device to the policy specified
    '''

    # Populate actions with either None or the action defined
    actions = {}
    for action in config['actions']:
        if config['actions'][action] == '':
            actions[action] = None
        else:
            actions[action] = config['actions'][action]

    log.debug(json.dumps(zs_report, indent=4))

    # Create/update watchlist feed
    if 'watchlist' in actions and actions['watchlist'] is not None:
        md5 = cb_event['md5']

        # Shorten vaiables
        Status = zs_report['Summary']['Status']
        Category = zs_report['Summary']['Category']
        FileType = zs_report['Summary']['FileType']
        StartTime = zs_report['Summary']['StartTime']
        Duration = zs_report['Summary']['Duration']
        Type = zs_report['Classification']['Type']
        Category = zs_report['Classification']['Category']
        Score = zs_report['Classification']['Score']
        DetectedMalware = zs_report['Classification']['DetectedMalware']

        # Build the Report arguments
        timestamp = convert_time(convert_time('now'))
        title = '{} - {} - {}'.format(md5, Type, Category)
        description = ' # '.join([
            'Status: {}',
            'Category: {}',
            'FileType: {}',
            'StartTime: {}',
            'Duration: {}',
            'Type: {}',
            'Category: {}',
            'Score: {}',
            'DetectedMalware: {}'
        ]).format(Status, Category, FileType, StartTime, Duration, Type, Category, Score, DetectedMalware)

        severity = int(int(Score) / 10)
        if severity == 0:
            severity = 1

        url = '{}/{}'.format(config['Zscaler']['url'], '#insights/web')
        tags = [Type, Category, FileType]

        # Get the feed ready
        if cb.iocs is None:
            cb.iocs = []

        # If the feed has already been pulled, it is cached in cb.feed
        if cb.feed is None:
            # Get the feed
            feed = cb.get_feed(feed_name=actions['watchlist'])

            # If the feed doesn't exist, create it
            if feed is None:
                summary = 'MD5 indicators that tested positive in Zscaler Sandbox for one of \
                           the following: {0}'.format(config['Zscaler']['bad_types'])
                feed = cb.create_feed(actions['watchlist'], config['Zscaler']['url'], summary)

        # If IOC is not tracked in watchlist, add it
        if md5 not in cb.iocs:
            # Build the Report. cb.create_report caches the new reports in cb.new_reports
            cb.create_report(timestamp, title, description, severity, url, tags, md5)

    # Send data to webhook
    if 'webhook' in actions and actions['webhook'] is not None:
        url = actions['webhook']
        headers = {
            'Content-Type': 'application/json'
        }
        body = {
            'cb_event': cb_event,
            'zs_report': zs_report
        }
        requests.post(url, headers=headers, json=body)

    # Run a script
    if 'script' in actions and actions['script'] is not None:
        log.info('[APP.PY] Running Script')
        device_id = str(cb_event['device_id'])
        process_id = str(cb_event['pid'])
        script_cwd = os.path.dirname(os.path.realpath(__file__))
        stdin = stdout = subprocess.PIPE

        # We only want to run the script once per process
        if device_id not in script_queue:
            script_queue[device_id] = []

        if process_id not in script_queue[device_id]:
            # Replace elements
            script = config['actions']['script']
            script = script.replace('{device_id}', device_id)
            script = script.replace('{command}', 'kill')
            script = script.replace('{argument}', process_id)
            script = script.split(' ')

            cmd = [os.path.join(script_cwd, script[0])]
            args = script[1:]

            log.info('[APP.PY] {0} {0}'.format(cmd, args))

            script_queue[device_id].append(process_id)
            # !!! do i need stdout and stdin?
            log.info('[APP.PY] Running action script: {0} {1}'.format(cmd, args))
            subprocess.Popen(cmd + args, stdout=stdout, stdin=stdin)

    # Isolate endpoint
    if 'isolate' in actions and actions['isolate'].lower() in ['true', '1']:
        cb.isolate_device(cb_event['device_id'])

    # Change device's policy
    if 'policy' in actions and actions['policy'] is not None:
        cb.update_policy(cb_event['device_id'], actions['policy'])


def process_events(events):
    '''
        Loops through CBTH processes or CBD events. If a hash is found in the database or from Zscaler
        then it passes the event and ZS Sandbox report to the take_action() method.

        Inputs
            events: A list of process or event objects

        Output: None
    '''

    report_cache = {}

    for event in events:

        # Sometimes CBD is missing the MD5. Not much we can do about it, so skip these.
        if 'md5' not in event:
            event['md5'] = None

        if event['md5'] is None:
            log.debug('[APP.PY] Missing MD5: {0}'.format(json.dumps(event, indent=4)))
            continue

        # Check to see if we know about this file in the database
        db_record = db.get_file(md5=event['md5'])

        # If we don't know about it
        if db_record is None:
            # Check to see if Zscaler knows about the file

            if event['md5'] in report_cache:
                zs_report = report_cache[event['md5']]
            else:
                zs_report = zs.get_report(event['md5'])
                report_cache[event['md5']] = zs_report

            # If Zscaler does know about it
            if zs_report not in [None, False]:
                zs_type = zs_report['Classification']['Type']
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
            cache_time = int(config['Zscaler']['unknown_cache'])

            # If the last report is more than `unknown_cache` days, check again
            if days >= cache_time:
                zs_report = zs.get_report(event['md5'])
                zs_type = zs_report['Classification']['Type']
                db.update_file(event['md5'], event['sha256'], zs_type)

            if status in zs.bad_types:
                zs_report = zs.get_report(event['md5'])
                take_action(event, zs_report)
    return


def get_processes():
    '''
        Uses the Platform APIs to pull all processes matching the criteria defined in the
            config file.
    '''
    # Get the start and end times
    # Start time comes from the datbase's last_pull time
    last_pull = convert_time(db.last_pull())
    buffer_time = 30 * 60  # 30 minutes
    start_time = convert_time(last_pull - buffer_time)

    # End time is the 'upper' of available span
    available_span = cb.get_available_span()
    end_time = convert_time(available_span['upper'])

    # Build the query based on start/end_time and process reputation from configs
    query = '(process_start_time:[{0} TO {1}])'.format(start_time, end_time)

    if 'reputation_filter' in config['CarbonBlack']:
        if config['CarbonBlack']['reputation_filter'] != '':
            filters = config['CarbonBlack']['reputation_filter'].split(',')
            filters = ' OR process_reputation:'.join(filters)
            query = '{0} AND (process_reputation:{1})'.format(query, filters)

    # Submit the query and get a list of processes unique by hash
    processes = cb.get_processes(query, db)

    # Update the last pull time
    db.last_pull(timestamp=convert_time(end_time))

    return processes


def main():
    # Get inits
    init()

    # Get CBTH processes since the last run
    events = get_processes()

    # Process events
    process_events(events)

    # If watchlists are enabled in take_action() and there were bad files, update the watchlist
    if cb.new_reports is not None and len(cb.new_reports):
        feed = cb.get_feed(feed_name=config['actions']['watchlist'])
        feed.append_reports(cb.new_reports)

    db.close()


if __name__ == '__main__':
    main()
