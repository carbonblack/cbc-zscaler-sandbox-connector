import os
import json

import sqlite3
from sqlite3 import Error

import time
from time import sleep
from datetime import datetime, timedelta

import requests


# Import CBC Basics
from cbapi.psc import CbPSCBaseAPI
from cbapi.psc.models import BaseAlert

# Import Defense
from cbapi.psc.defense import CbDefenseAPI
from cbapi.psc.defense.models import Event, Device

# Import ThreatHunter
from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.psc.threathunter import Process
from cbapi.psc.threathunter.models import Feed, Report


class CarbonBlack:
    '''
        This is a wrapper around CBAPI's PSC, Defense and ThreatHunter modules.
        Import this class to interact with the various CB endpoints.
    '''

    def __init__(self, config, log):
        '''
            Initialize the CarbonBlack class. Assign self variables for use
                throughout the script.

            Inputs:
                config loaded with the settings from the config.ini

            Outputs:
                self
        '''
        self.class_name = 'CarbonBlack'
        self.log = log
        self.log.info('[%s] Initializing', self.class_name)

        self.config = config
        self.url = config['CarbonBlack']['url']
        self.org_key = config['CarbonBlack']['org_key']
        self.api_id = config['CarbonBlack']['api_id']
        self.api_key = config['CarbonBlack']['api_key']
        self.cust_api_id = config['CarbonBlack']['custom_api_id']
        self.cust_api_key = config['CarbonBlack']['custom_api_key']
        self.lr_api_id = config['CarbonBlack']['lr_api_id']
        self.lr_api_key = config['CarbonBlack']['lr_api_key']
        self.cb = CbPSCBaseAPI(url=self.url, org_key=self.org_key,
                               token='{0}/{1}'.format(self.cust_api_key, self.cust_api_id))
        self.cbd = CbDefenseAPI(url=self.url, org_key=self.org_key,
                                token='{0}/{1}'.format(self.api_key, self.api_id))
        self.cbth = CbThreatHunterAPI(url=self.url, org_key=self.org_key,
                                      token='{0}/{1}'.format(self.cust_api_key, self.cust_api_id))
        # self.minimum_severity = int(config['CarbonBlack']['minimum_severity'])
        self.time_bounds = None
        self.device_id = None
        self.session_id = None
        self.supported_commands = None

    #
    # CBC Platform
    #
    def get_alerts(self):
        '''
            Pull alerts from the Platform API using CBAPI.

            Inputs:
                None

            Output:
                A list of alert objects
        '''

        self.log.info('[%s] Getting alerts', self.class_name)

        query = self.cb.select(BaseAlert)
        query = query.set_group_results(True)
        query = query.set_minimum_severity(self.minimum_severity)
        query = query.sort_by('first_event_time', 'DESC')
        alerts = list(query)

        self.log.info('[%s] Found {0} alerts'.format(len(alerts)), self.class_name)

        return alerts

    def get_device(self, device_id):
        return self.cbd.select(Device).where('device_id:{0}'.format(device_id)).first()

    def isolate_device(self, device_id):
        devices = self.get_device(device_id)
        # !!! How to isolate endpoint?

    def update_policy(self, device_id, policy_name):
        devices = self.get_device(device_id)
        for dev in devices:
            dev.policyName = policy_name
            dev.save()

    #
    # CBC Endpoint Standard
    #
    def get_events(self, timespan='3h', rows=2500, start=0):
        '''
            Get all events within the provided timespan.

            Inputs:
                timespan: The searchWindow from which to pull events [optional] (str)
                    3h for the past three hours
                    1d for the past one day - default
                    1w for the past one week
                    2w for the past two weeks
                    1m for the past one month
                    all for all

            Output:
                A list of event objects
        '''

        self.log.info('[%s] Getting events for the last {0}'.format(timespan), self.class_name)

        # events = self.cbd.select(Event).where('searchWindow:3h')
        # return events

        total_results = rows + 1
        unique_events = []
        event_tracking = []

        url = self.url + '/integrationServices/v3/event'
        params = {
            'searchWindow': timespan,
            'rows': rows,
            'start': start
        }
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': '{0}/{1}'.format(self.api_key, self.api_id)
        }

        while params['start'] <= total_results:
            r = requests.get(url=url, headers=headers, params=params)

            if r.status_code != 200:
                self.log.error('[%s] {0} Error: {1}'.format(r.status_code, r.text), self.class_name)

            data = r.json()
            for event in data['results']:
                # Update root with things that might be required later
                event['md5'] = event['selectedApp']['md5Hash']
                event['sha256'] = event['selectedApp']['sha256Hash']
                event['device_id'] = event['deviceDetails']['deviceId']
                event['pid'] = event['processDetails']['processId']

                if event['md5'] not in event_tracking:
                    event_tracking.append(event['md5'])
                    unique_events.append(event)

            params['start'] = params['start'] + rows
            total_results = data['totalResults']

        self.log.info('[%s] Found {0} unique events'.format(len(unique_events)), self.class_name)
        return unique_events

    def get_event(self, event_id):
        '''
            Grab a single event's details from CB Defense.

            Inputs:
                event_id: the ID of the event to be pulled
            Output:
                an object of the event, or the error message from a failed request
        '''

        self.log.info('[%s] Getting event details: {0}'.format(event_id), self.class_name)

        r_url = '{0}/integrationServices/v3/event/{1}'.format(self.url, event_id)
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': '{0}/{1}'.format(self.api_key, self.api_id)
        }
        r = requests.get(url=r_url, headers=headers)

        if r.status_code == 200:
            event = r.json()
            return event

        self.log.info('Error: {0}'.format(r.text))
        return r.text

    def get_events_by_sha256(self, sha256):
        '''
            Get all events related to a SHA256 hash.

            Inputs:
                sha256: Hash for which to filter events (str)

            Output:
                A list of event objects
        '''

        self.log.info('[%s] Getting events by SHA256: {0}'.format(sha256), self.class_name)

        events = list(self.cbd.select(Event).where('sha256Hash:{0}'.format(sha256)))

        self.log.info('[%s] Found {0} events with sha256 {1}'.format(len(events), sha256))
        return events

    #
    # CBC Enterprise EDR
    #
    def get_available_span(self):
        '''
            Gets the available data timeframes in CBC.

            Inputs: None

            Output:
                The JSON response of the request
        '''

        self.log.info('[%s] Getting available data timespan', self.class_name)

        endpoint = '{url}/threathunter/search/v1/orgs/{org_key}/processes/limits'.format(url=self.url,
                                                                                         org_key=self.org_key)
        headers = {
            'X-Auth-Token': '{api_key}/{api_id}'.format(api_key=self.api_key, api_id=self.api_id)
        }
        r = requests.get(url=endpoint, headers=headers)
        data = r.json()['time_bounds']

        self.log.info('[%s] Available time range is from {0} to {1}'.format(convert_time(data['lower']),
                                                                            convert_time(data['upper'])),
                      self.class_name)

        self.time_bounds = data

        return data

    def get_processes(self, query, db, rows=500, start=0):
        '''
            Get process search results from CBC Enterprise EDR

            Inputs:
                query: the query to be submitted (str)
                db: the database object for checking for duplicates (obj)
                rows: how many results to fetch at a time (int)
                start: where to start in the results (int)

            Outputs:
                Returns a list of processes
        '''

        self.log.info('[%s] Getting processes: {0}'.format(query), self.class_name)

        # Keep a dictionary of the processes to be returned
        processes = []

        # For filtering unique processes (hashes)
        unique_procs = []

        # Paginate through the processes
        procs = self.cbth.select(Process).where(query)  # .sort_by('first_event_time', 'DESC') # !!! need to figure out how to sort these

        # query.sort_by('first_event_time', 'DESC')
        for process in procs:
            # Filter out things we already checked
            if process.process_sha256 in unique_procs:
                continue
            unique_procs.append(process.process_sha256)

            # Get the raw JSON
            raw_proc = process.original_document

            if 'process_hash' not in raw_proc:
                self.log.info('[%s] Process is missing MD5 and SHA256. Skipping.', self.class_name)
                continue

            if len(raw_proc['process_hash']) == 1:
                if len(raw_proc['process_hash'][0]) == 32:
                    self.log.info('[%s] Process is missing the SHA256. Skipping.', self.class_name)
                    raw_proc['md5'] = raw_proc['process_hash'][0]
                    continue

                else:
                    self.log.info('[%s] Process is missing the MD5', self.class_name)
                    raw_proc['sha256'] = raw_proc['process_hash'][0]
                    metadata = self.ubs_get_metadata(raw_proc['process_hash'][0])

                    if metadata is not None:
                        raw_proc['md5'] = metadata['md5']

                    else:
                        self.log.info('[%s] Unable to get file metadata. Skipping.', self.class_name)
                        continue

            if len(raw_proc['process_hash']) == 2:
                raw_proc['md5'] = raw_proc['process_hash'][0]
                raw_proc['sha256'] = raw_proc['process_hash'][1]
                raw_proc['pid'] = raw_proc['process_pid'][0]

            # Save the JSON
            processes.append(raw_proc)

        self.log.info('[%s] Found {0} unique processes'.format(len(processes)), self.class_name)
        return processes

    def ubs_get_metadata(self, sha256):
        '''
            Pulls the metadata for a file. Sometimes the MD5 of a process
                isn't included in the process request. This will get the metadata
                of the file which does contain the MD5.

            Inputs:
                sha256: Hash of the file to be pulled

            Outputs:
                Raw JSON of the request
        '''

        self.log.info('[%s] Getting file metadata: {0}'.format(sha256), self.class_name)

        endpoint = '{url}/ubs/v1/orgs/{org_key}/sha256/{sha256}/metadata'.format(url=self.url,
                                                                                 org_key=self.org_key,
                                                                                 sha256=sha256)
        headers = {
            'X-Auth-Token': '{api_key}/{api_id}'.format(api_key=self.api_key,
                                                        api_id=self.api_id),
            'Content-Type': 'application/json'
        }
        r = requests.get(url=endpoint, headers=headers)
        if r.status_code == 200:
            self.log.info('[%s] Metadata found for file: {0}'.format(sha256), self.class_name)
            return r.json()
        else:
            self.log.info('[%s] Metadata NOT found for file: {0}'.format(sha256), self.class_name)
            return None

    def get_all_feeds(self):
        '''
            Pull all feeds from Enterprise EDR.

            Inputs: None

            Output:
                Raw JSON of all feeds
        '''

        self.log.info('[%s] Getting all feeds', self.class_name)

        feeds = self.cbth.select(Feed)
        self.log.info('[%s] Pulled {0} feeds'.format(len(feeds)), self.class_name)
        return feeds

    def get_feed(self, feed_id=None, feed_name=None):
        '''
            Gets the details for a single feed. If feed_name is provided, it will
                pull all feeds and filter by name. If feed_id is provided, it
                pulls based on that id.

            Inputs:
                feed_id: ID of the feed to pull (int)
                feed_name: Name of the feed to pull (str)

            Output:
                Raw JSON of the feed if one was found, otherwise None
        '''

        self.log.info('[%s] Getting feed: {0}'.format(feed_id), self.class_name)

        if feed_id is None and feed_name is None:
            self.log.info('[%s] Missing feed_id and feed_name. Need at least one', self.class_name)
            return None

        if feed_id is not None and feed_name is not None:
            self.log.info('[%s] Both feed_id and feed_name provided. Please only provide one', self.class_name)
            return None

        # if not isinstance(feed_id, int) or None:
        #     return None

        # if not isinstance(feed_name, str) or None:
        #     return None

        # If the feed_name was provided, get all the feeds and check their names
        if feed_name is not None:
            feeds = self.get_all_feeds()
            for feed in feeds:
                if feed.name == feed_name:
                    feed_id = feed.id
                    break

        self.log.info('feed_id: {0}'.format(feed_id))

        # If no feeds were found, return None
        if feed_id is None:
            return None

        feed = self.cbth.select(Feed, feed_id)

        self.log.info('[%s] Pulled feed {0} with name {1}'.format(feed_id, feed.name), self.class_name)
        return feed

    def create_feed(self, name, url, summary, report):
        '''
            Creates a new feed in CBC Enterprise EDR

            Inputs:
                name: Name of the feed to create (str)
                url: URL of the feed (str)
                summary: Summary of the feed (str)
                report: The initial report to add to the feed (obj)

            Output:
                An object of the newly created feed
        '''

        feed_info = {
            'name': name,
            'owner': self.org_key,
            'provider_url': url,
            'summary': summary,
            'category': 'Partner',
            'access': 'private',
        }

        feed = {
            "feedinfo": feed_info,
            "reports": [report]
        }

        feed = self.cbth.create(Feed, feed)
        feed.save()

        return feed

    def create_report(self, timestamp, title, description, severity, link, tags, md5):
        '''
            Creates a report for Enterprise EDR feeds

            Inputs:
                timestamp: Epoch timestamp to be added to the report (int)
                title: Title of the report (str)
                description: Description of the report (str)
                severity: Severity of the report (int)
                link: Link to report (str)
                tags: List of tags (list)
                md5: Hash IOC to be added to the report

            Output:
                An object of the newly created report
        '''

        self.log.info('[%s] Creating new feed:', self.class_name)

        report = {
            'timestamp': timestamp,
            'title': title,
            'description': description,
            'severity': severity,
            'link': link,
            'tags': tags,
            'iocs': [{
                'md5': [md5]
            }]
        }

        report = self.cbth.create(Report, report)

        self.log.info(report)
        return report

    def update_feed(self, feed_id, report):
        self.log.info('[%s] Updating feed: {0}'.format(feed_id), self.class_name)

    #
    # CBC Live Response helpers
    #
    def start_session(self, device_id, wait=False):
        '''
            Starts a CBC LiveResponse session. The session_id is saved in
                self.session_id

            Inputs:
                device_id: ID of the device to start the session on (int)
                wait: Hold the HTTP request while waiting for the session to establish (bool)

            Output:
                Raw JSON of the response. Contains the session_id for use later
        '''

        self.log.info('[%s] Starting LR session', self.class_name)
        url = '{0}/integrationServices/v3/cblr/session/{1}'.format(self.url, device_id)
        params = {'wait': wait}
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
        }
        r = requests.post(url, params=params, headers=headers)

        if r.status_code == 200:
            data = r.json()

            self.device_id = device_id
            self.session_id = data['id']
            self.supported_commands = data['supported_commands']

            self.log.info(json.dumps(data, indent=4))
            return data

        else:
            return r.text

    def get_session(self):
        '''
            Get the status of a session

            Inputs: None

            Output:
                Returns the raw JSON of the request
        '''

        if self.session_id is None:
            self.log.info('[%s] Cannot get session status. No session established'.format(self.session_id),
                          self.class_name)
            return 'No session established'

        self.log.info('[%s] Getting status of session: {0}'.format(self.session_id), self.class_name)

        url = '{0}/integrationServices/v3/cblr/session/{1}'.format(self.url, self.session_id)
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
        }
        r = requests.get(url, headers=headers)

        if r.status_code == 200:
            data = r.json()
            self.log.info(json.dumps(data, indent=4))
            self.supported_commands = data['supported_commands']

            return data
        else:
            return r.text

    def send_command(self, command, argument=None):
        '''
            Sends a LiveResponse command to an endpoint

            Inputs:
                command: Command to execute
                arguments: Supporting arguments for the command

            Output:
                Returns the raw JSON from the request
        '''

        self.log.info('[%s] Sending command to LR session: {0}'.format(command), self.class_name)

        if self.session_id is None:
            self.log.info('Error: no session')
            return 'Error: no session'

        if command not in self.supported_commands:
            self.log.info('Error: command not in available commands: {0}'.format(command))
            return 'Error: command not in available commands: {0}'.format(command)

        url = '{0}/integrationServices/v3/cblr/session/{1}/command'.format(self.url, self.session_id)
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
        }

        body = {
            'session_id': self.session_id,
            'name': command
        }
        if argument is not None:
            body['object'] = argument

        r = requests.post(url, headers=headers, json=body)

        data = r.json()

        self.log.info(json.dumps(data, indent=4))
        return data

    def command_status(self, command_id):
        '''
            Get the status of a previously submitted command

            Inputs:
                command_id: ID of the command previously submitted (int)

            Output:
                Raw JSON of the response
        '''

        self.log.info('[%s] Getting status of LR command: {0}'.format(command_id), self.class_name)

        if self.session_id is None:
            self.log.info('[%s] Cannot get session status. No session established'.format(self.session_id),
                          self.class_name)
            return 'No session established'

        self.log.info('[%s] Getting status of command: {0}'.format(command_id), self.class_name)

        url = '{0}/integrationServices/v3/cblr/session/{1}/command/{2}'.format(self.url, self.session_id, command_id)
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
        }
        r = requests.get(url, headers=headers)

        if r.status_code == 200:
            data = r.json()

            self.log.info(json.dumps(data, indent=4))
            return data
        else:
            return r.text

    def close_session(self):
        '''
            Closes a LiveResponse session.

            Inputs: None

            Outputs:
                Raw JSON response from the request

            > Note: When closing a LR session on an endpoint, if there are any
                other active sessions on that endpoint they will be closed as well.
        '''

        self.log.info('[%s] Closing session: {0}'.format(self.session_id), self.class_name)

        if self.session_id is None:
            self.log.info('Error: no session')
            return 'Error: no session'

        url = '{0}/integrationServices/v3/cblr/session'.format(self.url)
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
        }

        body = {
            'session_id': self.session_id,
            'status': 'CLOSE'
        }

        r = requests.put(url, headers=headers, json=body)

        data = r.json()

        self.log.info(json.dumps(data, indent=4))
        return data


class Database:
    def __init__(self, config, log):
        '''
            Initialise the database object. Create database and tables if they
                don't exist.

            Inputs:
                config: Dict containing settings from config.ini

            Output:
                self
        '''
        self.class_name = 'Database'
        self.log = log
        self.log.info('[%s] Initializing', self.class_name)

        self.config = config
        self.conn = None
        self.connect(config['sqlite3']['filename'])

        sql = [
            '''CREATE TABLE IF NOT EXISTS files (
                id integer PRIMARY KEY,
                timestamp text,
                md5 text,
                sha256 text,
                status text
            );''',

            '''CREATE TABLE IF NOT EXISTS alerts (
                id integer PRIMARY KEY,
                timestamp text
            );''',

            '''SELECT * FROM alerts'''
        ]

        try:
            cursor = self.conn.cursor()
            cursor.execute(sql[0])
            cursor.execute(sql[1])
            cursor.execute(sql[2])
            rows = cursor.fetchall()
            if len(rows) == 0:
                sql = '''INSERT INTO alerts(timestamp) VALUES(?)'''
                cursor.execute(sql, (convert_time('now'),))
                self.conn.commit()
                self.log.info('[%s] Created tables and added current timestamp as last pull time', self.class_name)
        except Error as e:
            self.log.info(e)

    def connect(self, db_file):
        '''
            Connects to the sqlite3 database

            Inputs:
                db_file: The name of the database file (str)

            Output:
                Returns an object of the connection
        '''

        self.log.info('[%s] Connecting to database: {0}'.format(db_file), self.class_name)
        if self.conn is not None:
            self.log.info('[%s] Connection is already established', self.class_name)
            return self.conn

        try:
            self.conn = sqlite3.connect(os.path.join(os.getcwd(), db_file))
            self.log.info('[%s] Connected to {0} using sqlite {1}'.format(db_file, sqlite3.version), self.class_name)
            return self.conn

        except Error as e:
            self.log.info(e)

    def close(self):
        '''
            Closes the database connection

            Inputs: None

            Output:
                Object of the closed connection
        '''

        self.log.info('[%s] Closing connection', self.class_name)

        if self.conn:
            self.conn.close()

        self.log.info('[%s] Connection closed', self.class_name)

    def get_file(self, md5=None, sha256=None):
        '''
            Looks for any rows in the database with the provided hash

            Inputs:
                md5: MD5 hash to search for in the database (str)
                sha256: SHA256 hash to search for in the database (str)

            Output:
                Returns any rows found matching the provided hash. If no results
                    were found, returns None
        '''

        if md5 is not None:
            item = md5
            item_type = 'md5'
        elif sha256 is not None:
            item = sha256
            item_type = 'sha256'
        else:
            self.log.error('[%s] No hash provided', self.class_name)
            return 'No hash provided'

        self.log.info('[%s] Getting hash by {0}: {1}'.format(item_type, item), self.class_name)
        sql = 'SELECT * FROM files WHERE {0} = ?'.format(item_type)

        cursor = self.conn.cursor()
        cursor.execute(sql, (item,))
        rows = cursor.fetchall()
        if len(rows) > 0:
            self.log.info('[%s] Found {0}: {1}'.format(item_type, item), self.class_name)
            return rows

        self.log.info('[%s] Unable to find hash by {0}: {1}'.format(item_type, item), self.class_name)
        return None

    def add_file(self, md5, sha256, status):
        '''
            Adds a file to the database

            Inputs:
                md5: MD5 hash to add to the row (str)
                sha256: SHA256 hash to add to the row (str)
                status: Status from Zscaler report (str)

            Output:
                Returns the row ID of the new entry
        '''

        if md5 is None:
            return 'Missing md5'
        if sha256 is None:
            return 'Missing sha256'
        if status is None:
            return 'Missing status'

        self.log.info('[%s] Adding file: MD5: {0}'.format(md5), self.class_name)

        if self.conn is None:
            return 'No connection to database'
        if self.get_file(md5=md5):
            return 'File already exists'

        timestamp = convert_time('now')
        file_info = (timestamp, md5, sha256, status,)
        sql = 'INSERT INTO files(timestamp,md5,sha256,status) VALUES(?,?,?,?)'
        cur = self.conn.cursor()
        cur.execute(sql, file_info)
        self.conn.commit()
        return cur.lastrowid

    def update_file(self, md5, sha256, status):
        '''
            Update a file in the database

            Inputs:
                md5: MD5 hash to add to the row (str)
                sha256: SHA256 hash to add to the row (str)
                status: Status from Zscaler report (str)

            Output:
                Returns the results of the new row
        '''

        self.log.info('[%s] Updating file: {0}'.format(md5), self.class_name)

        timestamp = convert_time('now')
        params = (timestamp, status, md5,)
        sql = 'UPDATE files(timestamp,status) SET timestamp = ?, status = ? WHERE md5 = ?'
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        self.conn.commit()

        return self.get_file(md5=md5)

    def last_pull(self, timestamp=None):
        '''
            Get or set the last pull time in the database

            Inputs:
                timestamp:
                    If None, get the last pull time from the database
                    Otherwise set the last pull time with either the epoch (int)
                        or ISO8601 format (str)

            Output:
                Returns the last pull timestamp from the database if timestamp is None
                Returns the database response if timestamp == epoch or ISO8601
        '''

        # Get or set last pull timestamp
        if timestamp is None:
            self.log.info('[%s] Getting last pull', self.class_name)
            sql = 'SELECT timestamp FROM alerts WHERE id = 1'
            cursor = self.conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            return rows[0][0]

        else:
            if isinstance(timestamp, int):
                timestamp = convert_time(timestamp)

            self.log.info('[%s] Update last pull: {0}'.format(timestamp), self.class_name)

            timestamp = (timestamp,)
            sql = 'UPDATE alerts SET timestamp = ? WHERE id = 1'
            cursor = self.conn.cursor()
            cursor.execute(sql, timestamp)
            self.conn.commit()


class Zscaler:
    '''
        A helper class for working with Zscaler's ZIA Sandbox.

        See Zscaler's API docs here: https://help.zscaler.com/zia/api
    '''

    def __init__(self, config, log):
        '''
            Initialize the Zscaler class

            Inputs:
                config: Dict containing settings from config.ini

            Output:
                self
        '''
        self.class_name = 'Zscaler'
        self.log = log
        self.log.info('[%s] Initializing', self.class_name)

        self.url = config['Zscaler']['url']
        self.api_key = config['Zscaler']['api_key']
        self.username = config['Zscaler']['username']
        self.password = config['Zscaler']['password']
        self.session = None
        self.quota = None
        self.bad_types = config['Zscaler']['bad_types'].split(',')
        self.headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': 'VMware Carbon Black Cloud Connector'
        }

    def _obfuscate_api_key(self):
        '''
            Zscaler's custom function for obfuscating the API key. See here
                for more info: https://help.zscaler.com/zia/api-getting-started

            Inputs: None

            Output:
                Returns current timestamp and obfuscated API key
        '''

        seed = self.api_key
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ''

        for i in range(0, len(str(n)), 1):
            key += seed[int(str(n)[i])]

        for j in range(0, len(str(r)), 1):
            key += seed[int(str(r)[j]) + 2]

        return now, key

    def start_session(self):
        '''
            Start a session with Zscaler's API. A request.session() is used to
                track the JSESSIONID cookie used for susequent API calls.

            Inputs: None

            Output:
                Raw JSON response from the request
        '''

        self.log.info('[%s] Starting session', self.class_name)
        timestamp, obf_api_key = self._obfuscate_api_key()

        url = '{}/api/v1/authenticatedSession'.format(self.url)
        headers = self.headers
        data = {
            'username': self.username,
            'password': self.password,
            'apiKey': obf_api_key,
            'timestamp': str(timestamp)
        }

        self.session = s = requests.Session()

        r = s.post(url, json=data, headers=headers)

        if r.status_code == 200:
            self.session_id = r.cookies['JSESSIONID']
            self.get_quota()
            self.log.info('[%s] Session established. JSESSIONID: {}'.format(self.session_id), self.class_name)

        # Return the session
        return s

    def get_report(self, md5):
        '''
            Gets a report from Zscaler's sandbox

            Inputs:
                md5: MD5 hash to search for

            Output:
                Raw JSON response of the request

            > Note: there is a blocking 1 second delay to throttle requests to
                Zscaler's sandbox (max 2/second)
        '''

        self.log.info('[%s] Checking file: {}'.format(md5), self.class_name)

        if self.quota is None:
            self.get_quota()

        if self.quota['unused'] == 0:
            self.log.info('[%s] All queries for the day have been used. Max is {0}'.format(self.quota['allowed']),
                          self.class_name)
            return False

        # Zscaler throttles to 2 requests per second
        sleep(0.5)

        # Get the report
        url = '{0}/api/v1/sandbox/report/{1}'.format(self.url, md5)
        headers = self.headers
        s = self.session
        r = s.get(url, headers=headers)

        if r.status_code == 200:
            self.quota['used'] += 1
            self.quota['unused'] -= 1

            # Output a warning on low request counts remaining
            if self.quota['unused'] < 100:
                self.log.info('[%s] There are only {0} sandbox queries remaining'.format(self.quota['unused']),
                              self.class_name)

            # If the response's Summary is a string, it's not a report
            zs_report = None if isinstance(r.json()['Summary'], str) else r.json()

            # If there was a report, return it
            if zs_report is not None:
                zs_type = zs_report['Summary']['Classification']['Type']
                self.log.info('[%s] Sandbox report Classification Type: {0}'.format(zs_type), self.class_name)
            else:
                self.log.info('[%s] Unknown file: {0}'.format(md5), self.class_name)
            return zs_report

        else:
            self.log.info('[%s] Error: Status Code: {0}'.format(r.status_code), self.class_name)
            self.log.info(r.text)
        return None

    def get_quota(self):
        '''
            Get the quota counts for sandbox usage. Default is 1,000 requests per day

            Inputs: None

            Output:
                Raw JSON response of the request
        '''

        self.log.info('[%s] Getting qouota', self.class_name)

        if self.session is None:
            self.start_session()

        # Get the report
        url = '{0}/api/v1/sandbox/report/quota'.format(self.url)
        headers = self.headers
        s = self.session
        r = s.get(url, headers=headers)

        if r.status_code == 200:
            data = r.json()[0]
            self.quota = data
            self.log.info('[%s] Quota used: {0} unused: {1} allowed: {2}'.format(data['used'],
                                                                                 data['unused'],
                                                                                 data['allowed']), self.class_name)


def convert_time(timestamp):
    '''
        Converts epoch or ISO8601 formatted timestamp

        Inputs:
            timestamp:
                epoch time (int)
                ISO8601 time (str)
                'now' (str)

        Output:
            If timestamp was epoch, returns ISO8601 version of timestamp
            If timestamp was ISO8601, returns epoch version of timestamp
            If timestamp was 'now', returns ISO8601 of current time
    '''

    if isinstance(timestamp, int):
        if len(str(timestamp)) == 13:
            timestamp = int(timestamp / 1000)

        utc_dt = datetime(1970, 1, 1) + timedelta(seconds=timestamp)
        converted_time = utc_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')

    else:
        if timestamp == 'now':
            return time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        utc_dt = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
        converted_time = int((utc_dt - datetime(1970, 1, 1)).total_seconds())

    return converted_time


def str2bool(item):
    return item.lower() in ['true', '1']
