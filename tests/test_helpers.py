import pytest
import configparser

from app.lib.helpers import *
import logging as log

from data.basics import *

config = configparser.ConfigParser()
config.read('app/config.conf')

log.basicConfig(filename=config['logging']['filename'], format='[%(asctime)s] <pid:%(process)d> %(message)s', level=log.ERROR)

db = Database(config, log)
cb = CarbonBlack(config, log)
zs = Zscaler(config, log)

# Test helpers.CarbonBlack methods
def test_get_device():
    # should return an object of a device
    assert isinstance(cb.get_device(DEVICE_ID), object) == True

def test_get_events():
    assert isinstance(cb.get_events(rows=100), list) == True

def test_get_event():
    assert isinstance(cb.get_event(EVENT_ID), object) == True

def test_get_events_by_sha256():
    assert isinstance(cb.get_events_by_sha256(SAMPLE_SHA256), list)

def test_get_available_span():
    assert isinstance(cb.get_available_span(), dict)

def test_get_processes():
    query = 'process_start_time:[2020-03-01T11:00:00.000Z TO 2020-03-02T12:00:00.000Z]'
    unique = False
    assert isinstance(cb.get_processes(query, db, unique), list)

def test_get_metadata():
    assert isinstance(cb.get_metadata(SAMPLE_SHA256), dict)

def test_get_all_feeds():
    assert isinstance(cb.get_all_feeds(), object)

def test_get_feed():
    # test successful request by feed_id
    assert isinstance(cb.get_feed(feed_id=FEED_ID), object) == True

    # test successful request by feed_name
    assert isinstance(cb.get_feed(feed_name=FEED_NAME), object) == True

    # test missing feed by feed_id
    TEMP_ID = '1234qwerasdfzxcv'
    assert cb.get_feed(feed_id=TEMP_ID) == None

    # test missing feed by feed_name
    TEMP_NAME = FEED_NAME + '_DOESNT_EXIST'
    assert cb.get_feed(feed_name=TEMP_NAME) == None

    # test missing feed_id and feed_name
    assert cb.get_feed() == False

    #test both feed_id and feed_name provided
    assert cb.get_feed(feed_id=FEED_ID, feed_name=FEED_NAME) == False

def test_create_feed():
    assert isinstance(cb.create_feed(FEED_NAME, FEED_URL, FEED_SUMMARY), object) == True

def test_create_report():
    REPORT = cb.create_report(TIMESTAMP, REPORT_TITLE, REPORT_DESCRIPTION, REPORT_SEVERITY,
                                       REPORT_LINK, REPORT_TAGS, SAMPLE_MD5)

    assert isinstance(REPORT, object) == True

    FEED = cb.get_feed(feed_name=FEED_NAME)
    FEED.append_reports(cb.new_reports)
    FEED.save()

def test_start_session():
    assert isinstance(cb.start_session(DEVICE_ID), dict) == True

def test_get_session():
    assert isinstance(cb.get_session(), dict) == True

def test_send_command():
    assert isinstance(cb.send_command(LR_COMMAND, argument=LR_ARGUMENT), dict) == True

def test_command_status():
    assert isinstance(cb.command_status(COMMAND_ID), dict) == True

def test_close_session():
    assert isinstance(cb.close_session(), dict) == True

# Test helper.Database methods
def test_connect():
    assert isinstance(db.connect(DATABASE_FILE), object) == True

def test_close():
    assert isinstance(db.close(), object) == True

def test_get_file():
    assert isinstance(db.get_file(md5=SAMPLE_MD5), (dict, None)) == True

def test_add_file():
    assert isinstance(db.add_file(SAMPLE_MD5, SAMPLE_SHA256, 'TESTING'), int) == True

def test_update_file():
    assert isinstance(db.update_file(SAMPLE_MD5, SAMPLE_SHA256, 'TEST_UPDATE'), dict) == True

def test_last_pull():
    assert isinstance(db.last_pull(), int) == True
    assert db.last_pull(timestamp=convert_time('now')) == True


# Test helper.Zscaler methods
def test_start_session():
    assert isinstance(zs.start_session(), object) == True

def test_get_report():
    assert isinstance(zs.get_report(SAMPLE_MD5), dict) == True

def test_get_quota():
    assert isinstance(zs.get_quota(), dict) == True

# Test helper methods
def test_convert_time():
    # assert helpers.convert_time('now')
    assert convert_time(EPOCH_TIMESTAMP) == ISO8601_TIMESTAMP
    assert convert_time(ISO8601_TIMESTAMP) == EPOCH_TIMESTAMP

def test_str2bool():
    assert str2bool(STR_TRUE) == True
    assert str2bool(STR_FALSE) == False

# if __name__ == '__main__':
#     test_get_device()