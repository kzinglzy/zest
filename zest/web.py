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
zest.web
~~~~~~~~

This module implement the core function for Web develop.
"""
import asyncio
import os
import mimetypes
import traceback
import sys
import urllib
from os.path import abspath, join, dirname
from functools import partial, lru_cache
from inspect import ismodule, isclass
from zest.core import is_async, Config, AsyncFile, get_param_length
from zest.httputil import (Request, Response, HTTPError,
                           JsonResponse, RedirectResponse)
from zest.helper import default_config
from zest.helper.util import get_logger, utc_time
from zest.helper.consts import ERROR_TEMPLETE, HTTP_STATUS
from zest.routing import Router


logger = get_logger('zest.web')


G_TEMPLATE_ENGINE = None  # global template engine.
G_TEMPLATE = {}           # global template variable or funtion
G_ROUTER = None           # global router


class App:

    """ The main entry of a Web app.

    Each App instance represents an WSGI application, which contains
    router, template, config, resources and so on.

    Parameters:
    - name: name of app, will have an affect at seraching the root path.
    - router: contaier of all the route.
    - config: config object, considered as a modules object. If not given,
        will initial from the default_config define at `helper.default_config`.
    - more_config: additional config. This will overwrite the previous config.

    NOTE:
        this application implement the WSGI inteface as a coroutine. When
        invoke this application  with other WSGI server, you must call with
        `yield from` syntax. For example:
            app = App()
            yield from app(environ, start_response)
    """

    default_template = 'mako'

    def __init__(self, name=None, router=None, config=None, **more_config):
        self.name = name
        self.router = router or Router()
        self.config = Config.from_module(config or default_config)
        self.config.update(**more_config)

        self.root_path = self.find_root_path(self.name)
        self.set_config('root_path', self.root_path)
        self.static_folder = self.get_config('static_folder', '').strip('/\\')
        self.static_path = abspath(join(self.root_path, self.static_folder))

        self.hooks = {}  # TODO
        self.error_handler = {}

        self.register_template(self.get_config('template_engine',
                                               self.default_template))
        global G_ROUTER
        G_ROUTER = self.router

    def find_root_path(self, name):
        """ Find the web application's root path from given module name.
        """
        if name:
            if name == '__main__':
                return os.getcwd()
            file = sys.modules[name].__file__
        else:
            import __main__ as x
            if ismodule(x) or isclass(x):
                if hasattr(x, '__module__'):
                    x = sys.modules[x.__module__]
                file = getattr(x, '__file__', None)

        return abspath(dirname(file))

    def register_template(self, template, **kwds):
        """ Register template engine.

        The default engine is 'mako'.
        You could easyily specify another engine just through inherit
        class `zest.template.Meta` or just provide a class object bring
        an 'render' method.
        """
        self.template_engine = None
        if isinstance(template, str):
            if template != 'mako':
                raise ValueError("Zest only support mako template engine now."
                                 "You could specify another engine through "
                                 "`zest.template` module or provide a class"
                                 "object bring an 'render' method.")
            from zest.template import Mako
            template = Mako
        assert hasattr(template, 'render'), "Invalid template engine."

        engine = template(**self.config)
        global G_TEMPLATE_ENGINE, G_TEMPLATE
        G_TEMPLATE_ENGINE = self.template_engine = engine

        G_TEMPLATE.update(**kwds)
        G_TEMPLATE['app'] = self
        G_TEMPLATE['config'] = self.config
        G_TEMPLATE['hooks'] = self.hooks

        return engine

    def add_template_global(self, name, value):
        """ Add a global template variable.

        Parameters:
        - name: variable name.
        - value: the object use in a template.
        """
        global G_TEMPLATE
        assert name not in G_TEMPLATE
        G_TEMPLATE[name] = value

    def global_template(self, name):
        """ Decorator to add template global variable.

        Usage:
            @global_template
            def template_func(*args, **kwds):
                do_something()

            ${template_func()}  # invoke at template.html
        """
        def deco(func):
            self.add_template_global(name, func)
            return func
        return deco

    @property
    def debug(self):
        return self.config['DEBUG']

    @debug.setter
    def debug(self, value):
        self.config['DEBUG'] = bool(value)

    @property
    def server_host(self):
        return self.config['SERVER_HOST']

    @property
    def server_port(self):
        return self.config['SERVER_PORT']

    def get_config(self, k, default=None):
        return self.config.get(k, default)

    def set_config(self, k, v, set_default=False):
        if set_default:
            self.config.setdefault(k, v)
        else:
            self.config[k] = v

    def trigger_hooks(self, name, *args, **kwds):
        """ Call a hook with given param
        """
        hook = self.hooks.get(name)
        if hook:
            return hook(*args, **kwds)

    def add_hook(self, name, func):
        self.hooks[name] = func
        return func

    def add_route(self, rule, controller, method='GET', priority=True):
        """ Bind a controller to it's corresponding route.

        Parameters:
        - rule: Regular expression or normal string. If rule contails a capture
            group, the capture group will pass to controller as a params tuple.
        - controller: function to handle request. This function must have at
            least one param and the first params will be pass on an `Request`
            instance, which represents the current request context.
        _ method: request method, default to be 'GET', could provide a method
            list to support multi method.
        - priority: the priority of rule. the rule have high priority will be
            match first. (default to be True)

        Equals to `router.add_route`
        """
        self.router.add_route(rule, controller, method, priority)

    def route(self, rule, method='GET', priority=True):
        """ Decorator to bind a controller to it's corresponding route.

        Usage:

            @app.route('/hello/(\w+)')
            def index(name):
                return 'Hello, %s' % name

        This will bind route '/hello/(\w+)' to `index` controller.
        """
        def deco(func):
            self.add_route(rule, func, method, priority)
            return func
        return deco

    def register_before_request(self, func):
        """ Register a function to called before we start to process request.
        """
        if get_param_length(func) > 1:
            raise ValueError("`before_request` should have at most one param.")

        self.add_hook('_before_request', func)

    def before_request(self, func):
        """ Decorator for register function to called before process request.

        Parameters:
        - func: function to be called. This function might have one or zero
            parameter. And once parameter is given, it will be pass on an
            `Request` instance, which represents the current request context.

        Usage:

            @app.before_request
            def abort_ip(request):
                if request.IP in FORBIDDEN:
                    abort(403)

            @app.before_request
            def db_init():
                init_the_db()

        The first will abort this request if the request iP is forbidden.
        The second will initalize database then continue to process request.
        """
        self.register_before_request(func)
        return func

    def handle_before_request(self, request):
        func = self.hooks.get('_before_request')
        if func:
            if get_param_length(func) == 1:
                func = partial(func, request)  # Pass current request context.
            return func()

    def register_after_request(self, func):
        """ Register a function to called after making a response.
        """
        self.add_hook('_after_request', func)

    def after_request(self, func):
        """ Decorator for register function to called before process request.

        Parameters:
        - func: function to be called after response. This function might have.
         one or zero parameter. And once param is given, it will be pass on an
            `Response` instance, which represents response for request.

        Usage:

            @app.after_request
            def abort_ip(response):
                response.set_header('Server', 'Zest')
                return response

        This will add a server header to all the response.
        """
        self.register_after_request(func)
        return func

    def handle_after_request(self, response):
        func = self.hooks.get('_after_request')
        if func:
            if get_param_length(func) == 1:
                rsp = func(response)
                if not rsp or not isinstance(rsp, Response):
                    raise ValueError('`after_request` must return a response.')
            else:
                rsp = func()
        else:
            rsp = response  # do nothing and return the same reponse.

        return rsp

    def add_error_handler(self, code, handler):
        """ Add a function to handle HTTP error.

        Parameters:
        - code: status of HTTP error
        - handler: function to handle error. This function might have one
            or no parameter. Once parameter is given, it will be pass on an
            `Request` instance, which represents the current request context.
        """
        self.error_handler[code] = handler

    def error(self, code):
        """ Decorator to add a error handler.

        Usage:

            @error(404)
            def handle_404():
                return render('404.html')
        """
        def deco(func):
            self.add_error_handler(code, func)
        return deco

    def merge_router(self, router):
        """ Merge routes with other router.

        Equals to `router.merge`
        """
        return self.router.merge(router)

    def get(self, rule, **kwds):
        """ Equals to `add_route(rule, method='GET', **kwds)`."""
        return self.router.get(rule, **kwds)

    def post(self, rule, **kwds):
        """ Equals to `add_route(rule, method='POST', **kwds)`."""
        return self.router.post(rule, **kwds)

    def delete(self, rule, **kwds):
        """ Equals to `add_route(rule, method='DELETE', **kwds)`."""
        return self.router.delete(rule, **kwds)

    def head(self, rule, **kwds):
        """ Equals to `add_route(rule, method='HEAD', **kwds)`."""
        return self.router.head(rule, **kwds)

    def log(self, msg):
        """ Logs messages from specify logger.
        """
        logger.info(msg)

    def log_exception(self, exc):
        """ Logs an exception.

        When debug model is set, log the traceback instead.
        """
        if self.debug:
            logger.error(traceback.format_exc())
        else:
            logger.error(exc)

    def add_static_handler(self, favicon_handler=None, static_handler=None):
        """ Add a default route to handle static file.
        """
        def _favicon_handler(request):
            return static_file('favicon.ico', self.root_path, request)

        def _static_handler(request, path):
            file_path, name = os.path.split(path)
            return static_file(name,
                               join(self.static_path, file_path.strip('/\\')),
                               request)

        self.add_route('/favicon\.ico', favicon_handler or _favicon_handler,
                       priority=False)
        self.add_route('/%s/(.*)' % self.static_folder,
                       static_handler or _static_handler, priority=False)

    def run(self, host=None, port=None, debug=False, **kwds):
        """ Runing server at specify address.

        Parameters:
        - host: server address to bind. (default to 127.0.0.1)
        - port: server port to bind. (default to 7676)
        - debug: develop and debugl model.(default to False)
        - autoreload: sets True to start `auto_reload` server.  # TODO
        - kwds: WSGI server setting. Go to `zest.server` for detail.
        """
        from zest.server import make_wsgi_server
        self.config.update_no_none(server_host=host, server_port=port,
                                   debug=bool(debug), **kwds)
        self.add_static_handler()

        host, port = self.server_host, self.server_port
        self.log('runing server at %s:%s' % (host, port))
        make_wsgi_server(app=self,
                         host=host,
                         port=port,
                         debug=self.debug,
                         **kwds)

    def match(self, request):
        """ Find a matching rule and return the corresponding controller.

        If find the matching rule but it has a bad request method, this
        will raise a 403 error. If not find, raise 404 error.
        """
        func, params = self.router.match_wsgi(request)
        if not func:
            if params == 403:  # match, but with no allow method
                raise HTTPError(403)
            else:              # can't find any rule match.
                raise HTTPError(404)
        else:
            if self.auto_unquote:
                try:
                    params = map(urllib.parse.unquote, params)
                except Exception as exc:
                    self.log_exception(exc)
            return partial(func, request, *params)

    def make_response(self, response, code=None):
        """ Create an response, return an Response instance.

        Parameter:
        - response: Response object or string or sequence.
        - code: response status code.
        """
        if response is None:
            raise ValueError("Can't response None.")

        rp = response
        if not isinstance(response, Response):
            body = headers = None
            code = code or 200
            if isinstance(response, (tuple, list)):
                body, code, headers = response + (None, ) * (3 - len(response))
            elif isinstance(response, str):
                body = response
            else:
                body = str(response)  # TODO
            rp = Response(body, headers, code)
        elif code is not None:
            rp.set_status(code)

        return rp

    @lru_cache(maxsize=100)
    def make_error_response(self, err, request=None):
        """ Create error response from HTTP error.
        """
        handler = self.error_handler.get(err.status)
        status = int(err.status)
        if not handler:
            reason = HTTP_STATUS.get(status)
            if not reason:
                status = 404  # reponse 404 while not reason find.
                reason = HTTP_STATUS[status]
            body = ERROR_TEMPLETE.format(status=status,
                                         reason=reason,
                                         message=err.message if self.debug
                                         else '')
            response = Response(body)
        else:
            if get_param_length(handler) == 1:
                response = handler(request)
            else:
                response = handler()

        return self.make_response(response, status)

    @asyncio.coroutine
    def response(self, environ, start_response):
        """ Respone from WSGI environ.
        """
        request = Request(environ)

        try:
            self.handle_before_request(request)

            rsp = self.match(request)()
            if is_async(rsp):
                rsp = yield from rsp
            response = self.make_response(rsp)
        except HTTPError as err:
            response = self.make_error_response(err, request)
        except Exception as exc:
            self.log_exception(exc)
            response = self.make_error_response(HTTPError(500))

        response = self.handle_after_request(response)
        return response.send(environ, start_response)

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        try:
            self.handle_before_request(request)
            rsp = self.match(request)()
            response = self.make_response(rsp)
        except HTTPError as err:
            response = self.make_error_response(err, request)
        except Exception as exc:
            self.log_exception(exc)
            response = self.make_error_response(HTTPError(500))

        response = self.handle_after_request(response)
        return response.send(environ, start_response)

    def __call__(self, environ, start_response):
        """ Implaments WSGI inteface for application.
        """
        return self.response(environ, start_response)

    def __getattr__(self, key):
        """ This method only gets called for attributes that don't exist.

        It's use to when some attributes not in the App instance. Just
        find from the config.
        """
        return self.config.get(key, None)

    def __repr__(self):
        return '<Application: %s>' % (self.name or '')


# Blow are some helpful tools


def static_file(name, path, request):
    """ Make a static file response.

    Parameters:
    - name: file name of static file.
    - path: absolute static directory path.
    - request: a `Request` object.

    ## This cool function is inspired by `bottle.static_file` then add a
    async read and write support
    """
    file_path = abspath(join(path, name.strip('/\\')))
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        raise HTTPError(404, 'File does not exist.')
    if not os.access(file_path, os.R_OK):
        raise HTTPError(403, 'You do not have permission to access this file.')

    headers = {}
    mimetype, encoding = mimetypes.guess_type(file_path)
    if mimetype:
        headers['Content-Type'] = mimetype
    else:
        headers['Content-Type'] = 'application/octet-stream'
        headers['Content-Disposition'] = 'attachment; filename="%s"' % name
    if encoding:
        headers['Content-Encoding'] = encoding

    stats = os.stat(file_path)
    headers['Content-Length'] = stats.st_size
    headers['Last-Modified'] = utc_time(stats.st_mtime)

    ims = request.if_modify_since
    if ims is not None and ims >= int(stats.st_mtime):
        response = Response(headers=headers, status=304)
    else:
        body = ''
        if request.method != 'HEAD':
            loop = request.event_loop
            with open(file_path, 'rb') as file:
                body = yield from AsyncFile(loop=loop, file=file).read()
        response = Response(body, headers)

    return response


def abort(status, message=''):
    """ Finish and response the request with specify status.

    Parameters:
    - status: integer number of response status.
    - message: string text of response body.
    """
    if not isinstance(status, int) or status not in HTTP_STATUS:
        raise ValueError("Invalid status code: %s." % status)
    raise HTTPError(status, message)


def redirect(path_or_url, status=303, response=None):
    """ Redict to specify url.

    Parameters:
    - path_or_url: redirect traget, could be a path or url, when it's a path,
         the redirect result will be: `request.url + path`.
    - status: response status. (default to be 303 For HTTP/1.1)
    - response: a `Response` object. (default to be None)
    """
    return RedirectResponse(path_or_url, status, response)


def to_json(*args, **kwds):
    """ Accept a key-value paris and convert to a Json response.

    Parameters:
    - args, kwds: the same with `dict` object.

    Usage:
        @app.get('/json')
        def json_controller(request):
            return to_json({'name': 'zest'})
    """
    return JsonResponse(*args, **kwds)


def render(name, **kwds):
    """ Render a template from template folder.

    Parameters:
    - name: template name to be rendered.
    - kwds: all the variable names (include the global custom variable)
        accessible to the template.
    """
    kwds.update(G_TEMPLATE)
    return Response(body=G_TEMPLATE_ENGINE.render(name, **kwds))


def url_for(url):
    pass


# TODO
def to_xml():
    pass


# TODO
def login_required():
    pass
