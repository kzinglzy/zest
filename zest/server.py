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
zest.server

This moudle provides an asynchronous server base on `asyncio`.
"""

import asyncio
import sys
import collections
import os
import traceback
from urllib.parse import unquote
from zest.core import HTTPHeaders, lazy_property, is_future, is_async
from zest.httputil import HTTPError
from zest.helper.util import utc_time, get_logger
from zest.helper.consts import HTTP_STATUS, ERROR_TEMPLETE

logger = get_logger('zest.server')


HTTPVersion = collections.namedtuple('http_version', 'major minor protocol')
HTTPStartLine = collections.namedtuple('http_startline', 'version status')
RequestMessage = collections.namedtuple(
    'request_message', 'command path version query close_coon headers'
)

CRLF = '\r\n'
bCRLF = b'\r\n'
SPACE = ' '
HEADER_END = '\r\n\r\n'
COLON = ':'


class Timeout(asyncio.TimeoutError):

    """ Raise by the operation exceeded the given deadline.

    Parameters:
    - seconds: a positive number value of timeout
    - handler: funtion will be called when timeout happen
    - loop: current event loop
    - exc: user-provided exception to be raise after timeout.
                set to False to prevent the exception spread.

    Useage:
        def timeout_hander():
            print('timeout')

        with Timeout(10, timeout_hander):
            time.sleep(10)
    """

    def __init__(self, seconds, handler, *, loop=None, exc=None):
        self.seconds = seconds
        self.handler = handler
        self.loop = loop or asyncio.get_event_loop()
        self.exc = exc
        self._timeout_handler = None

    def __enter__(self):
        self._is_timeout = False
        assert self.seconds >= 0
        if self.seconds > 0:
            self._timeout_handler = self.loop.call_later(self.seconds,
                                                         self._trigger_timeout)
        return self

    def __exit__(self, exc_type, exc_value, trace):
        if self._is_timeout:
            self.handler()
            if self.exc is not False:
                raise self.exc or self
            else:
                return True  # ignore this timeout exception
        elif self._timeout_handler:
            self._timeout_handler.cancel()
            self._timeout_handler = None

    def _trigger_timeout(self):
        self._is_timeout = True
        raise
        # TODO


class StreamReader(asyncio.streams.StreamReader):

    """ Add some userful methods to base StreamReader.
    """

    def _to_bytes(self, s):
        return bytes(s, 'utf-8') if not isinstance(s, bytes) else s

    @asyncio.coroutine
    def readuntil(self, stop, limit=0):
        """ Keep reading stream from buffer util find the stop flag.

        If buffer is empty or can't find a end pos, it will be sleep
        to wait until `feed_data` or `feed_eof` is called.
        """
        limit = limit or self._limit

        if self._exception is not None:
            raise self._exception

        stop = self._to_bytes(stop)
        result = bytearray()
        while True:
            pos = self._buffer.find(stop)
            if pos >= 0:
                size = pos + len(stop)
                if size > limit:
                    raise ValueError('Line is too long to %s.' % limit)
                else:
                    result.extend(self._buffer[:size])
                    del self._buffer[:size]
                    break
            elif self._eof:
                break
            else:
                yield from self._wait_for_data('readuntil')
        self._maybe_resume_transport()
        return bytes(result)

    @asyncio.coroutine
    def read_or_wait(self, wait=True):
        """ Read all the stream from buffer.

        If wait is set to True then it will be sleep to wait until
        `feed_data()` or `feed_eof()` is called, otherwise return None.
        """
        if self._exception is not None:
            raise self._exception

        if wait is True and not self._buffer and not self._eof:
            yield from self._wait_for_data('read_or_wait')
        result = bytearray()
        result.extend(self._buffer)
        del self._buffer[:]
        return bytes(result)


# TODO
class RFileReader(StreamReader):

    """ Provide a conforming `wsgi.input` value for request entities
    """
    zlib_obj = None

    def __init__(self, rfile, encoding=None):
        super().__init__()
        self.rfile = rfile
        self.encoding = encoding

    def feed_data(self, data):
        if self.encoding:
            # zlib_obj = zlib.decompressobj(
            #     wbits=16 + zlib.MAX_WBITS if self.encoding == 'gzip'
            #     else -zlib.MAX_WBITS
            # )
            # data = zlib_obj.decompress(data, 100)
            # self.zlib_obj = zlib_obj
            pass
        if data:
            super().feed_data(data)

    def feed_eof(self):
        if self.encoding:
            super().feed_data(self.zlib_obj.flush())
        super().feed_eof()


def is_valid_status(code):
    """ Check if a status code is avaliable.
    """
    return code in HTTP_STATUS


class HTTPCoonection:

    """ Implement the HTTP/1.x protocol. Base on RFC 2616.
    """
    DEFAULT_CTYPE = "text/html; charset=UTF-8"

    method = None
    path = None
    version = None
    status = None

    _parse_message = False
    _write_headers = False
    _write_chunk = False
    _write_chunk_eof = False

    def __init__(self, reader, writer, server, *, coding='utf-8',
                 max_body=65535, max_headers=65535):
        self.reader = reader
        self.writer = writer
        self.server = server

        self.coding = coding
        self.max_body = max_body
        self.max_headers = max_headers
        self._timeout = server._timeout
        self._timeout_handler = server.cancel_request
        self._loop = server.loop
        self._keep_alive = server._keep_alive

    @asyncio.coroutine
    def parse_message(self):
        """ Parse request line and request headers

        The first line of the request has the form
            <command> <path> <version>
        Return a namedtuple object when succeed, otherwise failue with
        HTTPError.
        """
        self._parse_message = True
        reader = self.reader

        line = yield from reader.readline()
        if line == CRLF:
            # RFC 2616 sec 4.1
            # Ignore the CRLF when it's at the beginning of a message.
            line = yield from reader.readline()
        line = line.decode(self.coding)

        if not line:
            raise asyncio.CancelledError
        if not line.endswith(CRLF):
            raise HTTPError(400, 'HTTP requires CRLF terminators')

        command, path, version, query = self._parse_request_line(line)
        self.command, self.path, self.version = command, path, version

        with Timeout(self._timeout, self._timeout_handler, loop=self._loop):
            lines = yield from reader.readuntil(HEADER_END)
        lines.decode(self.coding)

        headers = HTTPHeaders.from_lines(lines)

        connection = headers.get('Connection', '').lower()
        if (version.minor == 1 and connection == 'close') or \
                (version.minor == 0 and connection != 'keep-alive'):
            # HTTP/1.1 alwasys keep alive when HTTP/1.0 default to be close
            close_coon = True
        else:
            close_coon = False

        return RequestMessage(command, path, version, query,
                              close_coon, headers)

    def _parse_request_line(self, line):
        try:
            method, path, version = line.strip().split(None, 2)
            version = HTTPVersion(int(version[5]), int(version[7]), version)
        except (ValueError, IndexError):
            raise HTTPError(400, 'Malformed Request-Line')
        if version.major < 1:  # Http version should be 1.x
            raise HTTPError(505)
        query = ''
        if '?' in path:
            path, query = path.split('?', 1)

        return method, path, version, query

    @asyncio.coroutine
    def parse_body(self, headers):
        """ Parse the request payload and return a RFileReader object.
        """
        if not self._parse_message:
            raise Exception("Should read the request message first"
                            "before read the body")
        reader = self.reader
        body = RFileReader(reader, headers.get('Content-Encoding'))

        content_length = headers.get('Content-Length', 0, int)
        if content_length > self.max_body:
            raise HTTPError(413)

        chunk_read = False
        if self.version.minor == 1:  # Transfer_encoding only work for HTTP/1.1
            te = headers.get('Transfer-Encoding', '')
            if te:
                if te.lower() == "chunk":
                    chunk_read = True
                else:
                    raise HTTPError(501)  # only support 'chunk'

        if chunk_read:
            yield from self._read_chunk_body(reader, body)
        elif content_length > 0:
            yield from self._read_fixed_body(content_length, reader, body)
        elif self.command in ('PUT', 'POST'):
            # logger.warn("WARNING: Content-Length or Transfer-Encoding header"
            #             "is required with PUT or POST method.")
            yield from self._read_until_eof(reader, body)

        body.feed_eof()
        return body

    def _read_fixed_body(self, length, input_, output):
        assert length > 0, "Content length should be bigger than zero"
        while length:
            chunk = yield from input_.readexactly(length)
            length = len(chunk)
            if not length:
                logger.warn("WARNING: request body have not read enough "
                            "(maybe) because of a bad content length.")
                break
            output.feed_data(chunk)
            length -= len(chunk)

    def _read_chunk_body(self, input_, output):
        while True:
            chunk_len = yield from input_.readuntil(b"\r\n", limit=64)
            try:
                chunk_len = int(chunk_len.strip(), 16)
            except ValueError:
                raise HTTPError(400, 'Transfer encoding error')
            if chunk_len == 0:
                break
            yield from self._read_fixed_body(chunk_len, input_, output)
            yield from input_.readexactly(2)  # Skip the crlf \r\n

    def _read_until_eof(self, input_, output):
        output.feed_data((yield from input_.read_or_wait(False)))

    def _make_start_line(self, status, version=None):
        return (version or 'HTTP/1.1') + SPACE + str(status) + CRLF

    @asyncio.coroutine
    def simple_response(self, status, msg='', headers_dict=None):
        """ Make a simple response with specify status."""
        assert self.server.task is not None, "Server is closed"
        if not is_valid_status(status):
            raise Exception("HTTP status is invalid: %s." % status)

        message = msg or HTTP_STATUS[status]

        response = [self._make_start_line(status)]
        if headers_dict:
            response.extend(["%s: %s\r\n" % (k, v)
                             for k, v in headers_dict.items()])
        else:  # Add default headers
            response.extend(["Content-Length: %s\r\n" % len(message),
                             "Content-Type: text/plain\r\n"])
        response.append(CRLF)
        response.append(message)
        self.writer.write(''.join(response).encode('utf-8'))
        return (yield from self.write_eof())

    def write_headers(self, status, headers, version='HTTP/1.1'):
        """ Send headers to client.

        :param headers: HTTP headers, could be a dict, list or HTTPHeaders.
        """
        if not is_valid_status(status):
            raise Exception("HTTP status is invalid: %s" % status)
        try:
            if isinstance(headers, list):
                headers = HTTPHeaders.from_lists(headers)
            elif isinstance(headers, dict):
                headers = HTTPHeaders(headers)
        except Exception:
            raise ValueError("Invalid headers object")

        self._write_headers = True
        if not headers.get('Content-Length') and \
                version == 'HTTP/1.1' and status not in (204, 205, 304):
            self._write_chunk = True
            headers['Transfer-Encoding'] = 'chunked'

        if not headers.get('Connection'):
            if self.server._keep_alive and version == 'HTTP/1.1':
                coon = 'keep-alive'
            else:
                coon = 'close'
            headers.add('Connection', coon)

        if not headers.get('Content-Type'):
            headers.add('Content-Type', self.DEFAULT_CTYPE)
        if not headers.get('Date'):
            headers.add('Date', utc_time())
        if not headers.get('Server'):
            headers.add('Server', self.server.server_name)

        data = [self._make_start_line(status, version)]
        for k, v in headers.allitems():
            data.append(k + COLON + SPACE + str(v) + CRLF)
        data.append(CRLF)
        self.writer.write(''.join(data).encode('utf-8'))

    def write(self, chunk, encoding='utf-8'):
        """ Send chunk to client.

        You should always call `write_headers` before call this and
        call `write_eof` when all chunk is send.
        """
        assert self._write_headers is True, 'Should write headers first'

        if not isinstance(chunk, bytes):
            chunk = chunk.encode(encoding)

        if self._write_chunk:
            chunk = self._format_chunk(chunk)
        return self.writer.write(chunk)

    def _format_chunk(self, chunk):
        return b'%x\r\n%s%s' % (len(chunk), chunk, bCRLF)

    @asyncio.coroutine
    def write_eof(self):
        """ Complete to write chunk and flush the writer buffer."""
        if self._write_chunk:
            self.writer.write(b'0\r\n\r\n')
        # Succeed to send response, next response
        # should send headers again
        self._write_headers = False

        return (yield from self.writer.drain())


def _exception_callback(future):
    """ Catch the excption from Futures object.

    When Futures and Tasks set an excption: the exception is never log
    unless asks for this exception, so this func is try to catch the
    exception after a an excption have seted.
    """
    if future.exception():
        future.result()


class HTTPServer(asyncio.streams.FlowControlMixin, asyncio.Protocol):

    """ The async HTTP server protocol.

    Parameters:
    - loop: current event loop.
    - timeout: seconds time to cancel a slow request.(default to 15)
    - keep_alive: keep an request connection open.(default to True)
    - keep_alive_period: seconds time to close keepalive connection. only
        work when keep_alive is set to True.
    - debug: bool value to show more traceback infos.
    - if_ssl: bool value to use `https` or `http`.
    - server_name: string name show at the response's headers.

    Useage:
    >> loop = asyncio.get_event_loop()
    >> server = HTTPServer(*args, **kwds)
    >> asyncio.async(loop.create_server(server, host, port))
    >> loop.run_forever()
    """
    server_version = '0.0.1'
    http_version = 'HTTP/1.1'
    task = None

    def __init__(self, loop=None, timeout=15, keep_alive_period=75,
                 keep_alive=False, debug=False, is_ssl=False,
                 server_name=None, quiet=False):
        super().__init__(loop=loop)
        self.loop = loop or asyncio.get_event_loop()
        self._timeout = timeout
        self._keep_alive = keep_alive
        self._keep_alive_period = keep_alive
        self._keep_alive_handler = None
        self._debug = debug
        self._is_ssl = is_ssl
        self._server_name = server_name
        self._quiet = quiet

        self.reader = StreamReader(loop=loop)
        self.writer = None

    def connection_made(self, transport):
        """ An new HTTP connection entities is make, start to process.
        """
        self.transport = transport
        self.reader.set_transport(transport)
        self.writer = asyncio.streams.StreamWriter(
            transport, self, self.reader, self.loop)

        self.task = asyncio.async(self.start(), loop=self.loop)
        self.coon = HTTPCoonection(self.reader, self.writer, self)
        if self._debug:
            # only under debug model we will get the exception info,
            # else exception will be mute unless we manual call it.
            self.task.add_done_callback(_exception_callback)

    def data_received(self, data):
        self.reader.feed_data(data)

    def eof_received(self):
        self.reader.feed_eof()

    def connection_lost(self, exc):
        """ Request connection is closed.
        """
        super().connection_lost(exc)
        self.transport = self.writer = self.coon = None

        if exc is None:
            self.reader.feed_eof()
        else:
            self.reader.set_exception(exc)

        if self.task is not None:
            self.task.cancel()
            self.task = None
        if self._keep_alive_handler is not None:
            self._keep_alive_handler.cancel()
            self._keep_alive_handler = None

    @asyncio.coroutine
    def start(self):
        """ Start processing of incoming requests.
        """
        request = self.coon
        while True:
            try:
                # Before we parse the request body, we have to
                # stop the keep-alive timer to avoid the transport close.
                self.stop_keep_alive()

                message = yield from request.parse_message()
                body = yield from request.parse_body(message.headers)
                yield from self.handle_request(message, body)

            except Timeout:
                logger.warn('Parse timeout. Close this slow request.')
                break
            except asyncio.CancelledError:
                logger.debug('Ignored premature client disconnection.')
                break
            except HTTPError as err:
                self.log_http_error(err)
                yield from self.handle_error(err.status, err.message)
            except Exception as exc:
                self.log_exception(exc)
                yield from self.handle_error(500, exc if self._debug else '')
            else:
                self._keep_alive = False  # raise exception
            finally:
                if self.task:
                    if self._keep_alive:
                        self.start_keep_alive(self._keep_alive_period)
                    else:
                        self.task = None
                        self.transport.close()
                        break
                else:
                    break

    def cancel_request(self):
        """ Ignore and Close this request.
        """
        if self.task and not self.task.done():
            self.task.cancel()
            self.task = None
        if self.transport:
            self.transport.close()

    @lazy_property
    def server_name(self):
        return '%s:%s' % (self._server_name or 'zest', self.server_version)

    @lazy_property
    def peername(self):
        """ A tuple object for remote_addr and remote_port.
        """
        return self.transport.get_extra_info('peername')

    def start_keep_alive(self, sendos):
        """ Keep a request alive for sendos.
        """
        self._keep_alive_handler = self.loop.call_later(
            sendos, self.transport.close)

    def stop_keep_alive(self):
        """ Cancel the keep_alive task for request entities
        """
        if self._keep_alive_handler:
            self._keep_alive_handler.cancel()
            self._keep_alive_handler = None

    def set_timeout(self, timeout):
        self._timeout = timeout

    def set_debug(self, debug):
        self._debug = debug

    def shut_down_server(self):
        if self.loop.is_running():
            self.loop.stop()

    @asyncio.coroutine
    def handle_error(self, status, msg=''):
        """ Handle exception and send a specify status response.
        """
        try:
            status = int(status)
            reason = HTTP_STATUS.get(status)
            if not reason:
                reason = HTTP_STATUS[404]
                status = 400
            message = ERROR_TEMPLETE.format(status=status,
                                            reason=reason, message=msg)
            headers = {'Content-Type': 'text/html; charset=utf-8'}
            return (yield from self.coon.simple_response(status,
                                                         message, headers))
        except:
            logger.error(traceback.format_exc())
        finally:
            self._keep_alive = False

    @asyncio.coroutine
    def handle_request(self, message, body):
        """ Handle a single HTTP request then default to response 404.

        Override this method to make your response.
        """
        body = '404 Not Found'
        headers = HTTPHeaders({
            'Content-Type': 'text/plain',
            'Content-Length': len(body),
            'connection': 'keep-alive'
        })

        self.coon.write_headers(404, headers)
        self.coon.write(body)
        self.log_request(404, message)
        return (yield from self.coon.write_eof())

    def log_request(self, status, msg):
        if self._quiet:
            return
        status = status if is_valid_status(status) else 'UNKNOW'
        logger.info('%s %s' % (
                    status,
                    '%s %s' % (msg.command,  unquote(msg.path))
                    ))

    def log_http_error(self, err):
        status = err.status if is_valid_status(err.status) else 'UNKNOW'
        return logger.info('%s %s' % (status, err.request_line or
                                      'Internal Server Error'))

    def log_exception(self, exc):
        return logger.error(traceback.format_exc()) if self._debug \
            else logger.error(exc)

    def __call__(self):
        """ Process this class as protocol_factory for event loop.

        Since protocol_factory is called once for each new incoming
        connection, it should return a **new** Protocol object each time
        it is called.
        """
        return HTTPServer(self.loop, self._timeout, self._keep_alive_period,
                          self._keep_alive, self._debug, self.is_ssl,
                          self.server_name)


def make_http_server(host, port, **kwds):
    """ Start a HTTP server.

    Override the `handle_request` and `handle_error` to get your own response.
    """
    loop = asyncio.get_event_loop()
    server = HTTPServer
    srv = loop.create_server(server, host, port)
    try:
        asyncio.async(srv)
        loop.run_forever()
    finally:
        loop.close()


class WsgiServer(HTTPServer):

    """ Implement PEP-0333.
    """

    def __init__(self, app, *args, **kwds):
        super(WsgiServer, self).__init__(*args, **kwds)
        self.app = app
        self._args = args
        self._kwds = kwds

    def setup_environ(self, message, body):
        env = {
            'wsgi.input':           body,
            'wsgi.errors':          sys.stderr,
            'wsgi.version':         (1, 0),
            'wsgi.multithread':     False,
            'wsgi.multiprocess':    False,
            'wsgi.run_once':        False,
            'wsgi.url_scheme':      'https' if self._is_ssl else 'http',
            'REQUEST_METHOD':       message.command,
            'PATH_INFO':            message.path,
            'QUERY_STRING':         message.query,
            'REMOTE_ADDR':          self.peername[0],
            'REMOTE_PORT':          self.peername[1],
            'SERVER_NAME':          self.server_name,
            'SERVER_PROTOCOL':      self.http_version,
            'SERVER_PORT':          80 if not self._is_ssl else 443,
            'SCRIPT_NAME':          os.environ.get('SCRIPT_NAME', ''),
            'SERVER_CLASS':         self,
            'EVENT_LOOP':           self.loop,
        }
        for k, v in message.headers.items():
            if k == 'Content-Length':
                env['CONTENT_LENGTH'] = v
            elif k == 'Content-Type':
                env['CONTENT_TYPE'] = v
            else:
                env["HTTP_" + k.upper().replace("-", "_")] = v

        return env

    @asyncio.coroutine
    def handle_request(self, message, body):
        """ Call a WSGI application and make responses.
        """
        yield from self.async_run(message, body)
        # keep_alive = getattr(result, 'keep_alive', False)
        # if keep_alive is not None:
        #     self._keep_alive = keep_alive

    @asyncio.coroutine
    def async_run(self, message, body):
        """ Implement WSGI interface.
        """
        env = self.setup_environ(message, body)
        headers_set = []
        headers_sent = False

        def write(data):
            nonlocal headers_set, headers_sent
            if not headers_set:
                raise AssertionError("write() before start_response()")
            elif not headers_sent:
                status, headers = headers_set
                status = int(status[:3])
                self.coon.write_headers(status, headers, self.http_version)
                headers_sent = True
            self.coon.write(data)
            if self._quiet is False:
                self.log_request(status, message)

        def start_response(status, headers, exc_info=None):
            nonlocal headers_set, headers_sent
            if exc_info:
                try:
                    if self._send_headers:
                        for exc in exc_info:
                            raise exc
                finally:
                    exc_info = None
            elif headers_set:
                raise AssertionError("Headers already set!")
            headers_set[:] = [status, headers]
            return write

        response = self.app(env, start_response)
        try:
            if is_async(response):
                response = yield from response
            for data in response:
                if data:
                    if is_future(data):
                        data = yield from data
                    write(data)
            if not headers_sent:  # Send headers now if body was empty
                write('')
            yield from self.coon.write_eof()
        finally:
            if hasattr(response, 'close'):
                response.close()

        return response

    def __call__(self):
        """ Process this class as protocol_factory.
        """
        return WsgiServer(self.app, *self._args, **self._kwds)


def make_wsgi_server(app, host='127.0.0.1', port=7676, debug=False, **kwds):
    """ Start a WSGI server on specify host and port.

    Parameters:
    - host: server host.
    - port: server port, should be a positive integer.
    - app: a WSGI application to dispatch request and make response
    - debug: If set to True, will show more traceback info when error.
    - options kwds: another option for server. See `HTTPServer` for detail.
    """
    loop = asyncio.get_event_loop()
    server = WsgiServer(app, debug=debug, **kwds)
    srv = loop.create_server(server, host, port)
    try:
        asyncio.async(srv)
        loop.run_forever()
    finally:
        loop.close()
