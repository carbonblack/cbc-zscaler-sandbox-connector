from data import *
from app.lib.helpers import (convert_time, str2bool)
from data.basics import (
    EPOCH_TIMESTAMP,
    ISO8601_TIMESTAMP,
    STR_TRUE,
    STR_FALSE
)


def test_convert_time():
    # assert helpers.convert_time('now')
    assert convert_time(EPOCH_TIMESTAMP) == ISO8601_TIMESTAMP
    assert convert_time(ISO8601_TIMESTAMP) == EPOCH_TIMESTAMP

def test_str2bool():
    assert str2bool(STR_TRUE) == True
    assert str2bool(STR_FALSE) == False
