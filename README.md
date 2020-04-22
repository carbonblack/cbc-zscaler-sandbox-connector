# Zscaler ZIA Sandbox Connector for VMware Carbon Black Cloud

## Overview

This is an integration between **Zscaler's ZIA Sandbox** and **VMware Carbon Black Cloud (CBC) Endpoint Standard** and **CBC Enterprise EDR**. While Zscaler can scan all files before they reach the endpoint if they come through the network, what happens when a file comes in via another method, or prior to sensor installation?

The connector will scan for any CBC Enterprise Standard events or CBC Enterprise EDR processes. After pulling the processes it checks all of the unique hashes against a database of files that have been checked in the past. If the file is not known, a request to Zscaler's ZIA Sandbox is made to see if they have any information on it. If they do, or if the file is known bad from the local database, action is taken.

Action options consist of:
   - Adding to a CBC Enterprise EDR Watchlist Feed
   - Passing the event and sandbox report to a webhook
   - Running a script
   - Isolating the endpoint
   - Moving the endpoint into a policy

## Requirements
    - Python 3.x with sqlite3
    - VMware Carbon Black Cloud Endpoint Standard or Enterprise EDR
    - Zscaler ZIA with licensed Sandbox

----

## Installation

Clone the repository into a local folder.

    git clone git@github.com:carbonblack/cbc-zscaler-sandbox-connector.git

Install the requirements

    pip install -r requirements.txt

Edit the `config.conf` file and update with your configurations

## Configuration

All of the configurable settings for the integration can be found in [`config.conf`](https://github.com/carbonblack/cbc-zscaler-sandbox-connector/blob/master/app/config.conf).

### Carbon Black Configuration
You will need to create 1 API Access Level and 3 API keys

#### Custom Access Level Permissions

|       Category       |   Permission Name   |    .Notation Name   |       Create       |        Read        |       Update       | Delete | Execute |
|:--------------------|:-------------------|:-------------------|:------------------:|:------------------:|:------------------:|:------:|:-------:|
| Device               | General Information | device              |                    | :ballot_box_with_check: |                    |        |         |
| Device               | Policy assignment   | device.policy       |                    |                    | :ballot_box_with_check: |        |         |
| ThreatHunter         | Feeds               | threathunter.feeds  | :ballot_box_with_check: | :ballot_box_with_check: | :ballot_box_with_check: |        |         |
| ThreatHunter         | Events              | threathunter.events | :ballot_box_with_check: | :ballot_box_with_check: |                    |        |         |
| Unified Binary Store | SHA-256             | ubs.org.sha256      |                    | :ballot_box_with_check: |                    |        |         |

#### Access Levels (API key type)
1. API
2. Custom [Select your Custom Access Level]
3. Live Response (optional, used in action.py)

The Organization Key can be found in the upper-left of the **Settings** > **API Keys** page.
| CarbonBlack         | Configure Carbon Black Cloud       |
|:--------------------|:-----------------------------------|
| `url`               | URL of CBC instance                |
| `org_key`           | Org Key                            |
| `api_id`            | API ID                             |
| `api_key`           | API Secret Secret Key              |
| `custom_api_id`     | Custom API ID                      |
| `custom_api_key`    | Custom API Secret Key              |
| `lr_api_id`         | LiveResponse API ID                |
| `lr_api_key`        | LiveResponse API Secret Key        |
| `cbd_enabled`       | Enable CBC Endpoint Standard? [`true`/`false`] |
| `cbth_enabled`      | Enable CBC Enterprise EDR? [`true`/`false`] |
| `cbd_timespan`      | How far back to pull CB Defense events? [`3h`, `1d`, `1w`, `2w`,`1m`, `all`] |
| `reputation_filter` | Filter CB ThreatHunter processes by reputation. Default is `NOT_LISTED` |

----

### Zscaler Configuration

The API key can be found in **Administration** > **API Key Management**

| **Zscaler**         | **Configure Zscaler ZIA Access**   |
|:--------------------|:-----------------------------------|
| `url`               | URL for Zscaler ZIA                |
| `api_key`           | API Key                            |
| `username`          | Login Username                     |
| `password`          | Login Password                     |
| `bad_types`         | Bad Types in Sandbox Reports. [`MALICOUS`,`SUSPICIOUS`, `BENIGN`]|

----

Python 3.x ships by default with sqlite. If for some reason you don't have sqlite, you will need to install it (`pip install sqlite3`

| **sqlite3**         | **Configure sqlite3**              |
|:--------------------|:-----------------------------------|
| `filename`          | Filename of the sqlite3 database   |

----

When a file is detected to match the types defined in the `Zscaler` > `bad_types` configuration, actions are triggered. By default all actions are disabled.

#### watchlist  
When this field is populated, a Threat Feed is either created or updated with a Report of the detected file. The Report contains a short description, some tags and the severity from the Zscaler Sandbox report. Indicators are not duplicated if they already exist.

#### webhook
When this field is populated, a POST request is made to the http endpoint provided in the value of the configuration. The body of the POST request is an array of the Carbon Black event/process and the Zscaler report (`[cb_event, zs_report]`). Duplication may occur on this action.

#### script
When this field is populated, a script is executed at the path and with the parameters provided in the value of the configuration. There are 3 find/replace that occur (`{device_id}`, `{command}`, `{argument}`).

An example is provided in the [`config.conf`](). This will execute the provided example [action.py]() which will kill the triggered process.

#### isolate
When this field is populated with `true` the device will be isolated.

#### policy
When this field is populated, the device will be moved to the policy named with the configuration value. This is not the policy ID.

| **actions**         | **Configure Actions**              |
|:--------------------|:-----------------------------------|
| `watchlist`         | Name of watchlist to populate      |
| `webhook`           | URL to `POST` a JSON object of the event and sandbox report |
| `script`            | A script to execute                |
| `isolate`           | Isolate the endpoint?              |
| `policy`            | Policy to move offending devices   |

## Running the Script

The script has the following CLI options:

    optional arguments:
      -h, --help            show this help message and exit
      --last_pull LAST_PULL
                            Set the last pull time in ISO8601 format
      --cbd                 Pull CBD events
      --cbth                Pull CBTH processes

The `--last_pull` option overwrites the `last_pull` value stored in the database and will pull Cloud EDR processes since that time.

The `--cbd` and `--cbth` options will pull NGAV events and Cloud EDR processes respectively, even if they are disabled in the configuration file.

### Examples

Typical usage:

    python app.py
    
Specify Cloud EDR start date:

    python app.py --last_pull 2020-01-01T12:34:56.000Z