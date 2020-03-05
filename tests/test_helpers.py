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


def test_get_device():
    # should return an object of a device
    assert isinstance(cb.get_device(DEVICE_ID), object) == True

def test_get_events():
    assert isinstance(cb.get_events(rows=100), list) == True

def test_get_event():
    assert isinstance(cb.get_event(EVENT_ID), object) == True

def test_get_events_by_sha256():
    assert isinstance(cb.get_events_by_sha256(EVENT_SHA256), list)

def test_get_available_span():
    assert isinstance(cb.get_available_span(), dict)

def test_convert_time():
    # assert helpers.convert_time('now')
    assert convert_time(EPOCH_TIMESTAMP) == ISO8601_TIMESTAMP
    assert convert_time(ISO8601_TIMESTAMP) == EPOCH_TIMESTAMP

def test_str2bool():
    assert str2bool(STR_TRUE) == True
    assert str2bool(STR_FALSE) == False

if __name__ == '__main__':
    test_get_device()