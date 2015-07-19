# coding: utf8

# default
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 7676
IS_SSL = False
SERVER_NAME = None
DEBUG = False
KEEP_ALIVE = False
KEEP_ALIVE_PERIOD = 75
CALLBACK_ASYNC_RUN = False
AUTO_UNQUOTE = True

# static
STATIC_FOLDER = 'static'


# template
TEMPLATES_PATH = 'templates'
TEMPLATES_DIRECTORY = 'templates/_tmp'
INPUT_ENCODING = 'utf8'
OUTPUT_ENCODING = 'utf8'
FILTERS = ['trim', 'u', 'h']
DISABLE_UNICODE = False
ENCODING_ERRORS = 'ignore'
