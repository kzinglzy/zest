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
zest.httputil
~~~~~~~~~~~~~

This module provides some HTTP utils for zest
"""
# TODO: cache_control, etag, accept

import asyncio
import io
import cgi
import json
import re
import datetime
from wsgiref.util import request_uri
from http.cookies import SimpleCookie
from urllib.parse import unquote, parse_qs, urljoin
from zest.helper.util import timedelta_to_seconds, utc_time, utc_to_seconds
from zest.helper.consts import HTTP_STATUS
from zest.helper.exc import BaseExc
from zest.core import (cached_property, HTTPHeaders, WSGIHeaders,
                       MultiDict, immutable_dict, UserFile)


__all__ = ['Request', 'Response', 'HTTPError', 'RedirectResponse',
           'JsonResponse', 'XMLResponse']


# Regexp to parse charset in Content-Type
CHARSET_RE = re.compile(r';\s*charset=([^;]*)', re.I)


class Request:

    """ HTTP request from WSGI environ.
    """

    CHARSET = 'UTF-8'  # Default charset
    FORM_METHOD = ('POST', 'PUT', 'PATCH')
    FORM_CTYPE = ('',
                  'application/x-www-form-urlencoded', 'multipart/form-data',)

    def __init__(self, environ):
        self.env = environ
        self._post = None
        self._forms = None
        self._params = None
        self._files = None
        self._json = {}

    @cached_property
    def headers(self):
        """ HTTP Request headers.

        Return an read-only dict like and case-insensitive object.
        """
        return WSGIHeaders(self.env)

    def get_header(self, name, defalt=None, type_=None):
        """ Get single specify header.

        Parameters:
        - default: default value to return if find nothing
        - type_: set and try to format the result by execute type(value),
            if exception occur then return default.Default to be None.
        """
        return self.headers.get(name, defalt, type_)

    @cached_property
    def cookies(self):
        """ HTTP cookies.

        Return an read-only dict object.
        """
        return immutable_dict({
            k: v.value for k, v in
            SimpleCookie(self.get_header('Cookie', '')).items()
        })

    def get_cookie(self, key, default=None):
        """ Get single specify cookie."""
        return self.cookies.get(key, default)

    @property
    def remote_address(self, x_forwarded_for=False):
        """ Remote client's IP address str.

        If x_forwarded_for is set to True, this attribute returns the IP
        address of `HTTP_X_FORWARDED_FOR` header. If no, it return the value of
        `REMOTE_ADDR` header.

        But, Don't trust this value!!!. It maybe incorrect or forged by client.
        """
        if x_forwarded_for is True:
            xff = self.env.get('HTTP_X_FORWARDED_FOR')
            if xff:
                return xff.split(',')[0].strip()
        return self.env.get('REMOTE_ADDR')
    IP = remote_address  # alias for remote IP.

    @property
    def remote_port(self):
        """ Remote client request port."""
        return self.env['REMOTE_PORT']

    @property
    def content_length(self):
        """ The request body length. Always a positive inter or None."""
        length = self.env.get('CONTENT_LENGTH', None)
        try:
            return max(0, int(length))
        except (ValueError, TypeError):
            return None

    @property
    def content_type(self):
        """ HTTP request Content type.

        If the content_type does not include an optional character set encoding
        then it is identical to a mime_type.
        """
        return self.env.get('CONTENT_TYPE', '')

    @property
    def mine_type(self):
        """ The request content type without character set encoding."""
        return self.content_type.split(';')[0].lower()

    @cached_property
    def charset(self):
        """ Character set encoding specify in content_type or default value."""
        charset = CHARSET_RE.search(self.content_type)
        return charset.group(1) if charset else self.CHARSET

    @property
    def query_string(self):
        """ The url parameters string. Default to unquote."""
        return unquote(self.env.get('QUERY_STRING', ''))

    @cached_property
    def GET(self):
        """ All the variables from the query_string, wrapped by MultiDict.
        """
        h = MultiDict()
        for k, v in parse_qs(self.query_string).items():
            for val in v:
                h.add(k, val)
        return h

    def get_argument(self, key, default=None, type_=None):
        try:
            value = self.GET[key]
            if type_:
                value = type_(value)
        except Exception:
            return default
        else:
            return value

    @asyncio.coroutine
    def _get_body(self):
        body = bytearray()
        while True:
            chunk = yield from self.env['wsgi.input'].read_or_wait(wait=True)
            if not chunk:
                break
            body.extend(chunk)
        return bytes(body)

    @asyncio.coroutine
    def _read_post(self):
        """ Read All the variables from a form request and return a MultiDict.

        -- If your Pyhon version is below 3.4.4, you should note this
        issuse (https://bugs.python.org/issue23801) at cgi.FieldStorage.--
        """
        if self._post:
            return self._post

        if not (self.method in self.FORM_METHOD and
                self.mine_type in self.FORM_CTYPE):
            self._post = MultiDict()
        else:
            body = yield from self._get_body()
            fenv = self.env.copy()
            fenv['QUERY_STRING'] = ''
            fs = cgi.FieldStorage(fp=io.BytesIO(body),
                                  environ=fenv,
                                  keep_blank_values=True,
                                  encoding=self.charset)
            self._post = MultiDict.from_cgi_filedStoreage(fs)

        return self._post

    @property
    def forms(self):
        """ All the variables except the user upload file, wrapped by MultiDict.

        It should note that this attribute should be called with
        `yield from` syntax, such as:
            request_forms = yield from request.forms
        """
        if not self._forms:
            post = yield from self._read_post()
            self._forms = MultiDict.from_lists(filter(
                lambda x: not isinstance(x[1], UserFile),
                post.allitems()))

        return self._forms

    @property
    def files(self):
        """ The User upload file(is a UserFile object), wrapped by MultiDict.

        It should note that this attribute should be called with
        `yield from` syntax, such as:
            request_files = yield from request.files
        """
        if not self._files:
            post = yield from self._read_post()
            self._files = MultiDict.from_lists(filter(
                lambda x: isinstance(x[1], UserFile),
                post.allitems()))

        return self._files

    @property
    def params(self):
        """ All variables from query_string and request form, wrapped by MultiDict.

        It should note that this attribute should be called with
        `yield from` syntax, such as:
            request_params = yield from request.params
        """
        if not self._params:
            params = MultiDict.from_lists(self.GET.allitems())
            post = yield from self._read_post()
            for k, v in post.allitems():
                params.add(k, v)
            self._params = params

        return self._params

    @property
    def json(self):
        """ An dict object of JSON body when request mine_type is
        application/json, otherwise it is a empty dict.
        """
        if not self._json and self.mine_type in \
                ('application/json', 'application/x-www-form-urlencoded'):
            body = yield from self._get_body()
            if body:
                self._json = json.loads(
                    body.decode(self.charset).strip())
                return self._json
        return self._json

    @property
    def method(self):
        """An uppercase string represent the HTTP request method."""
        return self.env['REQUEST_METHOD']

    @property
    def path(self):
        """ Request path string, startswith a leading slash."""
        path = self.env.get('PATH_INFO', '')
        if not path.startswith('/'):
            path = '/' + path
        return path

    @property
    def full_path(self):
        """ Request path string, include the query_string."""
        if self.query_string:
            return self.path + '?' + self.query_string
        return self.path

    @property
    def url_scheme(self):
        """ Ulr scheme: https or http."""
        return self.env.get('wsgi.url_scheme')

    @property
    def script_name(self):
        return self.env.get('script_name')

    @property
    def host(self):
        """ Request host(without port)."""
        return '%s://%s%s' % (self.url_scheme,
                              self.env.get('HTTP_HOST', '').split(':')[0],
                              self.script_name or '/')

    @property
    def request_url(self):
        return self.host + self.path[1:]

    @property
    def http_version(self):
        """ Reqeust HTTP protocol."""
        version = self.headers.get('version')
        if version:
            return version.protocol

    @property
    def server_protocol(self):
        """ Server HTTP protocol."""
        return self.env['SERVER_PROTOCOL']

    @property
    def if_modify_since(self):
        ims = self.headers.get('if_modified_since')
        if ims:
            return utc_to_seconds(ims.split(";")[0].strip())

    @property
    def if_range(self):
        return self.headers.get('if_range')

    @property
    def range(self):
        """ HTTP range."""
        # TODO

    @property
    def ranges(self):
        """TO DO"""

    @property
    def event_loop(self):
        """ Current evnent loop."""
        return self.env['EVENT_LOOP']

    @property
    def _server(self):
        """ Current server object."""
        return self.env.get('SERVER_CLASS')

    def __iter__(self):
        yield from self.env

    def __repr__(self):
        return "<%s: %s %s>" % (self.__class__.__name__, self.method,
                                self.full_path)
    __str__ = __repr__


class Response:

    """ HTTP response object.
    """

    CHARSET = 'utf-8'  # default charset
    DEFAULT_CTYPE = "text/html; charset=UTF-8"  # default content_type

    def __init__(self, body='', headers=None, status=None, **kwds):
        if headers:
            if isinstance(headers, dict):
                headers = HTTPHeaders(headers)
            elif isinstance(headers, list):
                headers = HTTPHeaders.from_lists(headers)
        else:
            headers = HTTPHeaders()
        for k, v in kwds.items():  # More headers
            headers.add(k, v)
        self.headers = headers
        self.status = status or 200
        self._body = body or ''
        if not self.headers.get('Content-Length'):
            self.headers['Content-Length'] = str(len(self.body))

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, value):
        self._body = value
        self.headers['Content-Length'] = str(len(value))  # update

    def add_header(self, key, value):
        self.headers.add(key, value)

    def set_header(self, key, value):
        self.headers[key] = value

    def del_header(self, key):
        del self.headers[key]

    def set_headers(self, *args, **kwds):
        self.headers.update(*args, **kwds)

    @property
    def cookies(self):
        return self.headers.getall('Set-Cookie')

    def set_cookie(self, key, value, path='/', **params):
        """domain=None, path='/',
           expires=None, max_age=None, secure=None,
           httponly=None, comment=None, version=None
        """
        expires = params.get('expires')
        if expires:
            params['expires'] = utc_time(expires)
        max_age = params.get('max_age')
        if max_age and isinstance(max_age, datetime.timedelta):
            params['max_age'] = timedelta_to_seconds(max_age)

        cookie = SimpleCookie({key: value})
        cookie[key]['path'] = path
        for option, v in params.items():
            cookie[key][option.replace('_', '-')] = v

        self.headers.parse_header_line(cookie.output())

    def clear_cookie(self, key, path='/', domain=None):
        self.set_cookie(key, None, path=path, domain=domain)

    @property
    def charset(self):
        """ Character set encoding specify in content_type."""
        if self.content_type:
            match = CHARSET_RE.search(self.content_type)
            if match:
                return match.group(1)
        return self.CHARSET

    @charset.setter
    def charset(self, value):
        ctype = self.content_type
        if not ctype:
            raise AttributeError('Content-Type is require to set fist.')

        match = CHARSET_RE.search(ctype)
        if match:
            ctype = ctype[:match.start()] + ctype[match.end():]
        if value is not None:
            ctype = '%s;charset=%s' % (ctype, value)
        self.content_type = ctype

    def set_status(self, value):
        if isinstance(value, str):
            try:
                value = int(value)
            except:
                raise ValueError('Unvalid status value')
        if not (100 <= value <= 999):
            raise ValueError('Unvalid status value')
        self.status = value

    @property
    def content_type(self):
        return self.headers.get('Content-Type')

    def to_json(self):
        self.content_type = 'application/json; charset=UTF-8'
        self.body = json.dumps(self.body)

    @content_type.setter
    def content_type(self, value):
        self.headers['Content-Type'] = value

    @property
    def content_length(self):
        return self.headers.get('Content-Length')

    @property
    def location(self):
        return self.headers.get('Location')

    def close(self):
        pass  # Do nothing at all.

    def get_wsgi_status(self):
        return '%s %s' % (self.status, HTTP_STATUS.get(int(self.status), ''))

    def get_wsgi_body(self):
        body = self.body
        if not isinstance(body, bytes):
            body = body.encode(self.charset)
        return [body]

    def get_wsgi_headers(self, environ):
        headers = self.headers

        location = headers.get('location')
        if location and not location.startswith('http'):
            headers['location'] = urljoin(request_uri(environ), location)
        if not headers.get('Content-Length') and \
                not headers.get('Transfer_Encode'):
            headers['Content-Length'] = len(self.body)
        headers.setdefault('Content-Type', self.DEFAULT_CTYPE)

        return headers.to_wsgi_list()

    def _response_empty(self, environ):
        return environ['REQUEST_METHOD'] == 'HEAD' or \
            100 <= self.status < 200 or self.status == 204

    def __call__(self, environ, start_response):
        """ Implement WSGI interface.
        """
        start_response(self.get_wsgi_status(), self.get_wsgi_headers(environ))
        if self._response_empty(environ):
            return EmptyResponse(self.status, environ['REQUEST_METHOD'])
        return self
    send = __call__  # alias for call

    def __iter__(self):
        yield from self.get_wsgi_body()

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.status)
    __str__ = __repr__


class EmptyResponse:

    """ Empty response with empty body.
    """

    def __init__(self, status, method):
        self.status = status
        self.method = method

    def __iter__(self):
        return self

    def __len__(self):
        return 0

    def __bool__(self):
        return False

    def __next__(self):
        raise StopIteration()

    def __repr__(self):
        return "<%s: %s %s>" % ('Empty Response', self.status, self.method)
    __str__ = __repr__


class RedirectResponse(Response):

    """ Redirect to specify url.
    """
    MAX_LENGTH_URL = 2048  # http://stackoverflow.com/questions/417142

    def __init__(self, path_or_url, status=303, response=None):
        assert status in {301, 302, 303, 305, 307}, "Invalid redirect code."
        assert len(path_or_url) < self.MAX_LENGTH_URL, \
            "Request line too long, might contains an redirect cycle."

        body = ''
        headers = {}
        if response:
            body = response.body
            headers = response.headers
        headers.update({'Location': path_or_url})
        return super(RedirectResponse, self).__init__(body, headers, status)


class JsonResponse(Response):

    """ Json Response.

    Convert a dict or key-value paris to Json.
    """
    json_header = {'Content-Type': 'application/json; charset=UTF-8'}

    def __init__(self, *args, **kwds):
        body = json.dumps(dict(*args, **kwds))
        return super(JsonResponse, self).__init__(body, self.json_header)


class HTMLResponse(Response):

    """ HTML Response
    """

    def __init__(self):
        pass


class XMLResponse(Response):

    def __init__(self, *, body, **kwds):
        pass


class HTTPError(BaseExc):

    """ Raise by failue from a http request

    Parameters:
    - status: integer of an errore status code.
    - message: string obeject of detail messages.
    - req: an Request object.
    """
    __slots__ = ('status', 'message', 'request')

    def __init__(self, status, message='', request=None):
        self.status = status
        self.message = message
        self.request = request
        super(HTTPError, self).__init__()

    @property
    def request_line(self):
        return '%s %s' % (self.request.method, self.request.path) \
            if self.request else ''

    def __repr__(self):
        return "<%s: %s %s>" % ('HTTP Exception',  self.status, self.message)
    __str__ = __repr__
