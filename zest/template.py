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
zest.template

This module provides some HTML template utils.
"""

from abc import ABCMeta, abstractmethod
from os.path import join
from zest.core import Config


class Meta(metaclass=ABCMeta):

    def __init__(self, **kwds):
        self.conf = Config(**kwds)
        self.setup(self.conf)

    @abstractmethod
    def setup(self, **conf):
        """ Setting and init template.
        """

    @abstractmethod
    def render(template, **kwds):
        """ Render template
        """


class Mako(Meta):

    def setup(self, conf):
        from mako.lookup import TemplateLookup
        root = conf['root_path']
        self.loop_up = TemplateLookup(
            directories=join(root, conf['templates_path']),
            module_directory=join(root, conf['templates_directory']),
            input_encoding=conf['input_encoding'],
            output_encoding=conf['output_encoding'],
            disable_unicode=conf['disable_unicode'],
            encoding_errors=conf['encoding_errors'],
            filesystem_checks=conf['debug'],
            default_filters=conf.get('default_filters', []),
            imports=conf.get('imports', []),
            cache_enabled=(conf['debug'] is False)
        )

    def render(self, _template_name, **kwds):
        template = self.loop_up.get_template(_template_name)
        return template.render(**kwds)

    @classmethod
    def from_app(cls, app):
        app.register_template(cls)
