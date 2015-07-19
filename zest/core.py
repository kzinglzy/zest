#!/usr/bin/env python3
# coding: utf-8

# Copyright 2015 by kzing.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
zest.core
~~~~~~~~~

This moudle provides core utils for zest.
"""

import functools
import fcntl
import asyncio
import os
import inspect
import ctypes
import errno
from collections import MutableMapping
from types import MappingProxyType
from configparser import ConfigParser
from os.path import isfile
from zest.helper.util import safe_filename
from zest.helper.consts import CGI_KEYS
from zest.helper.exc import ImmutableTypeExc


def is_future(result):
    return isinstance(result, asyncio.Future)


def is_async(result):
    return asyncio.iscoroutine(result) or is_future(result)


class AsyncFile:

    """ Async file wrapper.
    """

    MAX_BLOCK_SIZE = 8192

    def __init__(self, *, loop=None, file=None, mode='rb'):
        if 'b' not in file.mode:
            raise RuntimeError('Only binary mode is supported')

        fl = fcntl.fcntl(file, fcntl.F_GETFL)
        if fcntl.fcntl(file, fcntl.F_SETFL, fl | os.O_NONBLOCK) != 0:
            errcode = ctypes.get_errno()
            raise OSError((errcode, errno.errorcode[errcode]))

        self.file = file
        self.loop = loop or asyncio.get_event_loop()
        self.buffer = bytearray()

    def seek(self, offset, whence=None):
        return self.file.seek(offset) if whence is None else \
            self.file.seek(offset, whence)

    @asyncio.coroutine
    def read(self, n=-1):
        future = asyncio.Future(loop=self.loop)
        if n == 0:
            future.set_result(b'')
        else:
            max_size = self.MAX_BLOCK_SIZE
            read_size = min(max_size, n) if n >= 0 else max_size
            self.buffer.clear()
            self.read_handler = self.loop.call_soon(self._read,
                                                    future, read_size, n)

        return future

    def _read(self, future, n, total):
        try:
            res = self.file.read(n)
        except Exception as exc:
            future.set_exception(exc)
        else:
            if res is None:   # Blocked
                self.read_handler = self.loop.call_soon(self._read,
                                                        future, n, total)
            elif not res:     # EOF
                future.set_result(bytes(self.buffer))
            else:
                self.buffer.extend(res)

                if total > 0:
                    read_more = total - len(self.buffer)
                    if read_more <= 0:  # Enough
                        res, self.buffer = self.buffer[:n], self.buffer[n:]
                        future.set_result(bytes(res))
                    else:
                        read_more_size = min(self.MAX_BLOCK_SIZE, read_more)
                        self.read_handler = self.loop.call_soon(
                            self._read, future, read_more_size, total)
                else:
                    self.read_handler = self.loop.call_soon(
                        self._read, future, self.MAX_BLOCK_SIZE,
                        total)

    @asyncio.coroutine
    def write(self, data):
        future = asyncio.Future(loop=self.loop)
        if len(data) == 0:
            future.set_result(0)
        else:
            self.write_handler = self.loop.call_soon(self._write, future,
                                                     data, 0)
        return future

    def _write(self, future, data, written):
        try:
            size = self.file.write(data)
        except BlockingIOError:
            self.write_handler = self.loop.call_soon(self._write, future,
                                                     data, written)
        except Exception as exc:
            future.set_exception(exc)
        else:
            total = written + size
            if size < len(data):
                data = data[size:]
                self.write_handler = self.loop.call_soon(self._write, future,
                                                         data, total)
            else:
                future.set_result(total)

    @asyncio.coroutine
    def copy_to(self, dest, copy_len=-1):
        copied_size = 0
        max_size = self.MAX_BLOCK_SIZE
        while copy_len != 0:
            read_size = min(copy_len, max_size) if copy_len > 0 else max_size

            rcontent = yield from self.read(read_size)
            rlen = len(rcontent)
            if rlen <= 0:
                break

            write_res = dest.write(rcontent)
            if is_async(write_res):
                yield from write_res
            copied_size += rlen
            copy_len = copy_len - len(rcontent) if copy_len > 0 else copy_len

        return copied_size

    def close(self):
        self.file.close()
        if hasattr(self, 'read_handler'):
            self.read_handler.cancel()
        if hasattr(self, 'write_handler'):
            self.write_handler.cancel()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.close()


def async_open(path):
    """ Helper to open a file. It's useful when open a large file.
    """
    if not os.path.exists(path) or not os.path.isfile(path):
        raise FileNotFoundError('File does not exist.')
    if not os.access(path, os.R_OK):
        raise Exception('You do not have permission to access this file.')
    with open(path, 'rb') as file:
        content = yield from AsyncFile(file=file).read()
    return content.decode('utf-8')


def open_in_executor(file_path, n, loop=None):
    """ Open file at a new threading.

    This will be little Slower than `async_open`.
    """
    def _read(file, n, output):
        with open(file_path, 'rb') as f:
            output.append(f.read(n))
    buffer = []
    loop = loop or asyncio.get_current_loop()
    yield from loop.run_in_executor(None, _read, file_path,
                                    n or 8192, buffer)
    return buffer[0]


class MultiDict(MutableMapping):

    """ A dict like object that key is case-insensitive and each key could
    have multi corresponding value.
    """
    __slots__ = ('_dict')

    def __init__(self, *args, **kwds):
        self._dict = {k: [v] for k, v in dict(*args, **kwds).items()}

    def add(self, k, v):
        self._dict.setdefault(k, []).append(v)

    @classmethod
    def from_lists(cls, lists):
        """ Parse from a lists like [(name, value), ...].
        """
        obj = cls()
        [obj.add(k, v) for k, v in lists]
        return obj

    @classmethod
    def from_cgi_filedStoreage(cls, fs):
        obj = cls()
        for item in fs.list or []:
            if item.filename:
                obj.add(item.name, UserFile(item.file, item.name,
                                            item.filename, item.headers))
            else:
                obj.add(item.name, item.value)
        return obj

    def get(self, k, default=None, side_func=None):
        """ Return the most recent value for a key

        :param default: default value when key isn't exist
        """
        value = self._dict.get(k)
        value = value[-1] if value else default
        if side_func:
            value = side_func(value)
        return value

    def getall(self, k):
        return self._dict.get(k, [])

    def keys(self):
        return self._dict.keys()
    iterkeys = keys

    def values(self):
        return (v[-1] for v in self._dict.values())
    itervalues = values

    def iteritems(self):
        return ((k, v[-1]) for k, v in self._dict.items())

    def items(self):
        return list(self.iteritems())

    def iterallitems(self):
        return ((k, v) for k, val in self._dict.items() for v in val)

    def allitems(self):
        return list(self.iterallitems())

    def __setitem__(self, k, v):
        self._dict[k] = [v]

    def __getitem__(self, k):
        return self._dict[k][-1]

    def __delitem__(self, k):
        del self._dict[k]

    def __contains__(self, k):
        return k in self._dict

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict)


@functools.lru_cache(maxsize=1000)
def _header_key(key):
    return key.title().replace('_', '-')


def _to_utf8(s):
    return s.decode('utf-8') if isinstance(s, bytes) else s


class HTTPHeaders(MultiDict):

    __slots__ = ('_dict')

    def __init__(self, *args, **kwds):
        self._dict = {
            _header_key(k): [str(v)]
            for k, v in dict(*args, **kwds).items()
        }

    def add(self, k, v):
        self._dict.setdefault(_header_key(k), []).append(v)

    def get(self, k, default=None, side_func=None):
        """ Return the most recent value for a key

        :param default: default value when key isn't exist
        """
        value = self._dict.get(_header_key(k))
        value = value[-1] if value else default
        if side_func:
            value = side_func(value)
        return value

    def getall(self, k):
        return self._dict.get(_header_key(k), [])

    def parse_header_line(self, line):
        if line.count(':') >= 1:
            k, v = line.split(':', 1)
            self.add(k, v.strip())

    def parse_header_lines(self, lines):
        """ Parse from a HTTP header bytes text
        """
        for line in _to_utf8(lines).split('\r\n'):
            self.parse_header_line(line)
        return self

    @classmethod
    def from_lines(cls, lines):
        """ Helper to create header dict from HTTP header bytes text
        """
        return cls().parse_header_lines(lines)

    def to_wsgi_list(self):
        """ Converts to [(key, value)] list
        """
        return [(str(k), str(v)) for k, val in self._dict.items() for v in val]

    def __setitem__(self, k, v):
        self._dict[_header_key(k)] = [v]

    def __getitem__(self, k):
        return self._dict[_header_key(k)][-1]

    def __delitem__(self, k):
        del self._dict[_header_key(k)]

    def __contains__(self, k):
        return _header_key(k) in self._dict


@functools.lru_cache(maxsize=1000)
def _header_key_2_wsgi_key(k):
    k = k.replace('-', '_').upper()
    if k not in CGI_KEYS and not k.startswith('HTTP_'):
        k = 'HTTP_' + k
    return k


@functools.lru_cache(maxsize=1000)
def _wsgi_key_2_header_key(k):
    if k.startswith('HTTP_'):
        return k[5:]
    elif k in CGI_KEYS:
        return k


class ImmutableMixIn:

    def __setitem__(self, k, v):
        raise ImmutableTypeExc("%s is Read-Only" % self.__class__)

    def __delitem__(self, k):
        raise ImmutableTypeExc("%s is Read-Only" % self.__class__)


class WSGIHeaders(ImmutableMixIn, MutableMapping):

    """ Read-Only dict like object to wrap a WSGI environ dict.

    Convenient to access the 'HTTP_' fileds.
    """
    __slots__ = ('env')

    def __init__(self, environ):
        self.env = environ

    def __getitem__(self, k):
        return self.env[_header_key_2_wsgi_key(k)]

    def __contains__(self, k):
        return _header_key_2_wsgi_key(k) in self.env

    def keys(self):
        return list(self.__iter__())

    def __len__(self):
        return len(self.keys())

    def __iter__(self):
        for k in self.env:
            key = _wsgi_key_2_header_key(k)
            if key:
                yield key

    def copy(self):
        return WSGIHeaders(self.env)

    def get(self, key, default=None, side_func=None):
        value = self.env.get(_header_key_2_wsgi_key(key)) or default
        if side_func:
            value = side_func(value)
        return value


class CachedProperty(object):

    """ A decorator that cache a property to instance object.

    Implemented as a non-data descriptor, which are only invoked if there is
    no entry with the same name in the instance's __dict__ or cls.__dict__.
    Usage:
    class Foo:
        @CachedProperty
        def some_property(self):
            print('I will only compute once.')
    """

    def __init__(self, func):
        functools.update_wrapper(self, func, updated=[])
        self.func = func

    def __get__(self, instance, cls):
        if not instance:
            return self
        value = self.func(instance)
        setattr(instance, self.func.__name__, value)
        return value
cached_property = CachedProperty


class LazyProperty(object):

    """ A decorator that caches a property to the class object.

    Behaves like the `CachedProperty`.
    """

    def __init__(self, func):
        functools.update_wrapper(self, func, updated=[])
        self.func = func

    def __get__(self, instance, cls):
        value = self.func(instance)
        setattr(cls, self.__name__, value)
        return value
lazy_property = LazyProperty


class Config(MutableMapping):

    """ Dict to store config.
    """

    __slots__ = ('_dict')

    def __init__(self, *args, **kwds):
        self._dict = {}
        self.update(*args, **kwds)

    def filter(self, prefix=''):
        """ Return a new config with specify prefix.

        From the given prefix find the key start with 'prefix' + '_' to make
        a new config. And the new config's key will have no prefix.
        """
        prefix = prefix.strip().lower() + '_'
        length = len(prefix)
        return Config({
            k[length:]: v
            for k, v in self.items()
            if k.startswith(prefix)
        })

    def update_no_none(self, _none_list=(None, ), **kwds):
        """ Update dict but not allows `None` value.
        """
        for k, v in kwds.items():
            if v in _none_list:
                continue
            self[k] = v

    @classmethod
    def from_config_file(cls, file_path):
        """ Parse from a config file(*.init, *.cfg).
        """
        if not isfile(file_path):
            raise FileNotFoundError()
        config = cls()
        parser = ConfigParser()
        parser.read(file_path)
        for section in parser.sections():
            for k, v in parser.items(section):
                if section.upper() != 'DEFAULT':
                    config.setdefault(section, {}).setdefault(k, v)
        return config

    @classmethod
    def from_module(cls, module):
        """ Parse from a normal Python module.

        All items define as a (key = value) paris. For example:
            # config.py
            HOST = 127.0.1.1
            PORT = 7676
        """
        assert inspect.ismodule(module), 'A module object is required.'
        config = cls()
        for key in dir(module):
            if key.isupper():
                config[key] = getattr(module, key)
        return config

    def __getitem__(self, key):
        return self._dict[key.lower()]

    def __setitem__(self, key, value):
        self._dict[key.lower()] = value

    def __delitem__(self, key):
        del self._dict[key.lower()]

    def __iter__(self):
        yield from self._dict.keys()

    def __len__(self):
        return len(self._dict)


# TODO
class UserFile:

    """ User upload file wrapper.
    """

    def __init__(self, fileobj, filename, name, headers):
        self.file = fileobj
        self.filename = safe_filename(filename)
        self.name = name
        self.headers = headers
        # super(UserFile, self).__init__(file=fileobj)


def get_param_length(func):
    """ Return a given function's length of it's parameters.
    """
    return int(func.__code__.co_argcount)


def param_check(func, *args, limit=0):
    """ Check given function have the same parameters as specify parameters.

    Parameters:
    - func: function to be compare.
    - args: parameter lists.
    - limit: number limit of compare.
    """
    code = func.__code__

    if limit:
        return args[:limit] == code.co_varnames[:limit]
    else:
        length = len(args)
        return code.co_argcount == length and args == code.co_varnames[:length]


def param_length_check(func, length, op):
    """ Check given function's param length.

    Parameters:
    - length: target length.
    - op: operation to compare
    """
    return op(get_param_length(func), length)


def find_caller(func):
    """ Find the caller by given function
    """
    pass


def immutable_dict(x):
    """ Create a immutable dict from dict or a list contains
    paris (key, value)
    """
    if isinstance(x, dict):
        return MappingProxyType(x)
    elif isinstance(x, list):
        return MappingProxyType({k: v for k, v in x})
