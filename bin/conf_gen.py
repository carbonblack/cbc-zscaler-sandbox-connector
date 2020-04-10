#!/usr/bin/env python3
import os

cb_url = os.environ.get('URL')
org_key = os.environ.get('ORG_KEY')
cb_api_key = os.environ.get('CB_API_KEY')
api_id = os.environ.get('API_ID')
custom_api_id = os.environ.get('CUSTOM_API_ID')
custom_api_key = os.environ.get('CUSTOM_API_KEY')
lr_api_id = os.environ.get('LR_API_ID')
lr_api_key = os.environ.get('LR_API_KEY')
z_url = os.environ.get('Z_URL')
z_api_key = os.environ.get('Z_API_KEY')
username = os.environ.get('USERNAME')
password = os.environ.get('PASSWORD')


config_file = """
; Configure logging
[logging]
enabled = True
filename = app.log
log_level = debug

; Configure VMware Carbon Black Cloud
[CarbonBlack]
url = %s
org_key = %s
api_id = %s
api_key = %s
custom_api_id = %s
custom_api_key = %s
lr_api_id = %s
lr_api_key = %s
cbd_enabled = False
cbth_enabled = False
reputation_filter = NOT_LISTED

; Configure Zscaler ZIA Sandbox
[Zscaler]
url = %s
api_key = %s
username = %s
password = %s
bad_types = MALICIOUS,SUSPICIOUS

; Configure sqlite database
[sqlite3]
filename = database.sql

; Actions to take on positive results
; Leave anything you want disabled blank
[actions]
; If you want to create a watchlist of the hashes, enter a watchlist name (will be created if doesn't exist)
; watchlist =

; If you want to send the data to a webhook as a POST, enter the URL
webhook =

; If you want to run a script for each results, enter the script here
; script =
script = action.py --device_id {device_id} --command {command} --argument {argument}

; If you want to move the device to a policy, enter the policy name here
policy =

; If you want to isolate the host, change to True
isolate = False
""" % (cb_url, org_key, api_id, cb_api_key, custom_api_id, custom_api_key, lr_api_id, lr_api_key, z_url, z_api_key,
       username, password)


f = open('app/config.conf', 'w')

f.write(config_file)
f.close()
