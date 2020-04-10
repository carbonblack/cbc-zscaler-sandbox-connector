from uuid import uuid4

# Sample data
SAMPLE_MD5 = '9d48ca0c5b5f2fe50880772eb65b77de'
SAMPLE_SHA256 = 'dd191a5b23df92e12a8852291f9fb5ed594b76a28a5a464418442584afd1e048'
RANDOM_MD5 = str(uuid4()).replace('-', '')
RANDOM_SHA256 = RANDOM_MD5 * 2

EPOCH_TIMESTAMP = 1583271346
ISO8601_TIMESTAMP = '2020-03-03T21:35:46.000Z'
STR_TRUE = 'True'
STR_FALSE = 'False'
DEVICE_ID = 3238121
EVENT_ID = '8343e1a96ada11ea9c9dc9e9e6b799ac'

# Feeds
FEED_ID = 'cs5PP7knQ6aebnSaNBQrDQ'
FEED_NAME = 'Sample Feed'
FEED_URL = 'https://test.com'
FEED_SUMMARY = 'Test feed'
TIMESTAMP = 1583860281
REPORT_TITLE = 'Sample report title'
REPORT_DESCRIPTION = 'Sample report description'
REPORT_SEVERITY = 5
REPORT_LINK = 'https://test.com/report'
REPORT_TAGS = ['TAG1', 'TAG2']

# Live Response
LR_COMMAND = 'directory list'
LR_ARGUMENT = 'C:\\Users\\'
COMMAND_ID = 4

# Database
DATABASE_FILE = 'tests/test_database.sql'
