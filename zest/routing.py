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
zest.routing
~~~~~~~~~~~~

This module provides URL routing for zest.
"""
import re
import inspect
from collections import deque
from zest.helper.exc import ControllerExc
from zest.core import get_param_length


#: This will match a simple uri that only contains Numbers,
#: Character, Dash - , Underscore _ , or Tilda ~.
SIMPLE_RULE = re.compile(r'(^[/0-9a-zA-Z-_~]+$)')


class Route:

    """ Map a uri to controller.
    """
    is_simple = True   # Flag to check if the rule is simple rule

    def __init__(self, router, rule, controller, method):
        self.rule = rule
        self.controller = controller
        if isinstance(method, str):
            method = {method}
        self.require_method = set(method)
        self._re_rule = self.make_re_rule(rule)

    def make_re_rule(self, rule):
        """ Contruct a regexp rule.

        If the rule is make up of simple `Character` or `Numbers` or special
        character: `_-~`, we will return a raw rule instead of compile it, so
        We can qukcily match a rule just by checking if the two rule is equals.
        """
        if SIMPLE_RULE.match(rule):
            return rule
        else:
            self.is_simple = False
            if not rule.endswith('$'):
                rule += '$'
            return re.compile(rule)

    def match(self, rule, method):
        """ Match a rule and return a RE_MATCH object.

        If complete match, return a (controller, params) of tuple.
        If match the rule but not the method, return a (None, 403) of tuple,
        otherwise return a (None, None) tuple.
        """
        match_rule = False
        match_method = method in self.require_method
        params = ()

        if self.is_simple:
            if rule == self._re_rule:
                match_rule = True
        else:
            m = self._re_rule.match(rule)
            if m:
                match_rule = True
                params = m.groups()

        if match_rule and match_method:
            return self.controller, params
        elif match_rule and not match_method:
            return None, 403
        else:
            return None, None

    def __repr__(self):
        return "<%s: '%s' -> %s >" % ('Route', self.rule,
                                      self.controller.__name__)


class Router:

    """ Map URI and it's correspoding controller.

    Parameters:
    - name: name of router.
    - prefix: a string use as the prefix of rule. Note that if prefix
            is provided, all rules will startswith ` prefix + '/' `.

    Usage:
        router = Router()

        @router.route('/')
        def index():
            pass

        @router.route('/user/(/w+)/(/d+)', method="POST)
        def user(name, age):
            pass
    """

    __slots__ = ('name', 'map', 'prefix', 'exist', 'controllers')

    def __init__(self, prefix=None, name=None):
        self.name = name or __name__.split('.', 1)[-1]
        self.exist = set()
        self.controllers = {}

        #: Map object is an `deque`, so it can provide the `append_left` method
        #: Because we have to ensure the complex rule is behind the simple rule
        #: For example, if there is two rule in the map:
        #:             ['/name/(\w+)', '/name/joe'],
        #: Cause the map object is ordered, so it's obviously that the latter
        #: rule will never match. So we put the complex rule to the right side
        #: (for delay it's match) and put the simple rule to the left side.
        self.map = deque()
        if prefix is not None:
            prefix = '/' + prefix.strip('/')
        self.prefix = prefix

    def match(self, rule, method='GET'):
        """ Find the correspoding controller from a given rule.

        Return a (controller, func_params) tuple
        """
        is_403 = False
        for route in self.map:
            controller, params = route.match(rule, method)
            if controller:
                return controller, params
            elif params == 403:
                is_403 = True

        return None, 403 if is_403 else None

    def match_wsgi(self, request):
        """ Match a rule from WSGI request.
        """
        return self.match(request.path, request.method)

    def route(self, rule, method='GET', priority=True):
        """ A decorator to add new rule.
        """
        def deco(f):
            self.add_route(rule, f, method, priority)
            return f
        return deco

    def add_route(self, rule, controller, method='GET', priority=True):
        """ Add rule with controller.

        Parameters:
        - rule: Regular expression or normal string.
        - controller: correspoding func of rule.
        - method: HTTP request method.(default to 'GET')
        - priority: the priority of rule. the rule have high priority will be
            match first.
        """
        self.controller_check(rule, controller)

        if self.prefix:
            rule = self.prefix + rule
        route = Route(self, rule, controller, method)
        if priority and route.is_simple:
            self.map.appendleft(route)
        else:
            self.map.append(route)

        self.exist.add(rule)
        self.controllers[controller.__name__] = rule

    def controller_check(self, rule, func):
        """ Check if the given route is avaliable.
        """
        if rule in self.exist:
            raise ValueError('Duplicate define rote rule: %s .' % rule)
        if not isinstance(rule, str):
            raise ValueError('Route rule should be a str.')
        elif not rule.startswith('/'):
            raise ValueError('Route rule should start with /.')
        if not inspect.isfunction(func):
            raise ValueError('Controller should be function type, not %s .'
                             % type(func))

        if get_param_length(func) < 1:
            # To ensure each controller could receive an
            # `Request` object as it's first param.
            raise ControllerExc()

    def merge(self, other):
        """ Merge the route with another router.

        # TODO. Sort
        """
        if not isinstance(other, Router):
            raise ValueError("Unsupported type for %s" % type(other))
        self.map.extend(other.map)
        return self.map

    def get(self, rule, **kwds):
        """ Equals to `add_route(rule, method='GET', **kwds)`
        """
        return self.route(rule, method='GET', **kwds)

    def post(self, rule, **kwds):
        """ Equals to `add_route(rule, method='post', **kwds)`
        """
        return self.route(rule, method='POST', **kwds)

    def delete(self, rule, **kwds):
        """ Equals to `add_route(rule, method='delete', **kwds)`
        """
        return self.route(rule, method='delete', **kwds)

    def head(self, rule, **kwds):
        """ Equals to `add_route(rule, method='head', **kwds)`
        """
        return self.route(rule, method='head', **kwds)

    def url_for(self, url, **kwds):
        pass

    def __repr__(self):
        return '<%s: %s>' % ('Router', self.name)
