# Zscaler ZIA Sandbox Connector for VMware Carbon Black Cloud

## Overview

This is an integration between Zscaler's ZIA Sandbox and VMware's Carbon Black Cloud (CBC) Endpoint Standard and CBC Enterprise EDR. While Zscaler can scan all files before they reach the endpoint if they come through the network, what happens when a file comes in via another method, or prior to sensor installation?

The connector will scan on a regular interval for any CBC Enterprise Standard events or CBC Enterprise EDR processes. After pulling the processes it checks all of the unique hashes against a database of files that have been checked in the past. If the file is not known, a request to Zscaler's ZIA Sandbox is made to see if they have any information on it. If they do, or if the file is known bad from the local database, action is taken.

Action options consist of:
    - Adding to a CBC Enterprise EDR Watchlist Feed
    - Passing the event and sandbox report to a webhook
    - Isolating the endpoint
    - Moving the endpoint into a policy
    - Running a script

## Requirements
    - Python 3.x
    - Internet connection

----

## Installation

Clone the repository into a local folder.

Install the requirements

    pip install -r requirements.txt

Edit the `config.conf` file and update with your configurations

## Configuration

All of the configurable settings for the integration can be found in `config.conf`.

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
| `cbd_enabled`       | Enable CBC Endpoint Standard?      |
| `cbth_enabled`      | Enable CBC Enterprise EDR?         |
| `filters`           | What reputation types to filter on |
| `cbd_timespan`      | How far back to pull CB Defense events? Options are: `3h`, `1d`, `1w`, `2w`,`1m`, `all` |
| `reputation_filter` | Filter CB ThreatHunter processes by reputation. Default is `NOT_LISTED` |

| **Zscaler**         | **Configure Zscaler ZIA Access**   |
|:--------------------|:-----------------------------------|
| `url`               | URL for Zscaler ZIA                |
| `api_key`           | API Key                            |
| `username`          | Login Username                     |
| `password`          | Login Password                     |
| `bad_types`         | Bad Types in Sandbox Reports. Default is `MALICOUS,SUSPICIOUS`      |

| **sqlite3**         | **Configure sqlite3**              |
|:--------------------|:-----------------------------------|
| `filename`          | Filename of the sqlite3 database   |

| **actions**         | **Configure Actions**              |
|:--------------------|:-----------------------------------|
| `watchlist`         | Name of watchlist to populate      |
| `webhook`           | URL to `POST` a JSON object of the event and sandbox report |
| `script`            | A script to execute                |
| `isolate`           | Isolate the endpoint?              |
| `policy`            | Policy to move offending devices   |
