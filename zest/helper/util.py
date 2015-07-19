#!/usr/bin/env python3
# coding: utf-8
import logging
import datetime
import string
from email.utils import parsedate


def get_logger(name):
    """ Logger helper.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s ",
                                  "%Y-%m-%d %H:%M:%S")

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


def utc_time(dt=None):
    """ Converts datetime to HTTP/1.1 UTC time string.

    e.g. 'Mon, 13 Apr 2015 06:33:57 GMT'
    """
    if isinstance(dt, (float, int)):
        dt = datetime.datetime.utcfromtimestamp(dt)
    if not dt:
        dt = datetime.datetime.utcnow()
    return dt.strftime('%a, %d %b %Y %H:%M:%S GMT')


def utc_to_datetime(s):
    """ Converts a HTTP/1.1 UTC time string to datetime object.
    """
    return datetime.datetime(*parsedate(s.strip())[:6])


def utc_to_seconds(s):
    """ Converts a HTTP/1.1 UTC time string to seconds.
    """
    t = utc_to_datetime(s) - datetime.datetime(1970, 1, 1)
    return t.total_seconds()


def timedelta_to_seconds(delta):
    """ Converts datetime.delta to seconds.
    """
    if isinstance(delta, datetime.delta):
        return delta.days * 86400 + delta.seconds


def safe_filename(name):
    SAFE_CHARS = string.ascii_letters + string.digits + " -_."
    try:
        return ''.join(filter(lambda c: c in SAFE_CHARS, name))
    except Exception:
        return 'empty'
