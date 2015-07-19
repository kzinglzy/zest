#!/usr/bin/env python3
# coding: utf-8
from zest.core import (MultiDict, HTTPHeaders, WSGIHeaders,
                       Config, cached_property, param_check)
from zest.helper.exc import ImmutableTypeExc
import pytest


def test_multi_dict(cgi_filed):
    mdict = MultiDict({'name': 'jack', 'age': 22}, country='US')
    assert len(mdict) == 3

    mdict.add('name', 'rose')
    assert mdict['name'] == mdict.get('name') == 'rose'
    assert mdict.get('age') == 22
    assert mdict.get('age', side_func=lambda v: v + 1) == 23
    assert mdict.get('inexistence', default='default') == 'default'

    assert len(mdict.getall('name')) == 2
    assert mdict.getall('inexistence') == []

    items = mdict.allitems()
    assert len(items) == 4
    assert len(MultiDict.from_lists(items)) == 3

    mdict = MultiDict.from_cgi_filedStoreage(cgi_filed)
    assert mdict['cgi'].headers == {'k': 'v'}


def test_http_header_dict(http):

    hdict = HTTPHeaders(http.header)

    assert len(hdict) == 3
    assert hdict['Content_Encoding']
    assert hdict.get('ContentType') is None

    hdict.add('Server', 'pyzest.com')
    hdict.add('Content-Encoding', 'deflate') and hdict['Content-Encoding']
    assert hdict.getall('Content_Encoding') == ['gzip', 'deflate']

    hdict = HTTPHeaders.from_lines(http.header_line)
    assert hdict['Connection'] == 'keep-alive'
    HTTPHeaders.from_lines(http.b_header_line)

    wsgi_header = hdict.to_wsgi_list()
    assert isinstance(wsgi_header, list)
    assert len(wsgi_header) == 2


def test_wsgi_header_dict(http):
    wdict = WSGIHeaders(http.wsgi_header)
    assert len(wdict.items()) == 3
    assert wdict['Cache_Control'] == wdict['HTTP_CACHE_CONTROL'] == 'no_cache'

    assert wdict.get('Cache_Control') == 'no_cache'
    assert wdict.get('inexistence') is None
    assert wdict.get('inexistence', 'default') == 'default'
    assert wdict.get('inexistence', side_func=lambda k: 'foo') == 'foo'

    assert id(wdict) != id(wdict.copy())

    with pytest.raises(ImmutableTypeExc):
        wdict['WSGI_KEY'] = 'some value'


def test_config_dict():
    conf = Config({'A': 1, 'B': 2}, C=3)
    assert len(conf) == 3

    # conf = Config.from_module(config_module)
    # assert "debug" in conf and "DEBUG" in conf and "DeBUg" in conf
    # conf['UPPER_KEY'] = 'UPPER_VALUE'
    # assert conf.get('upper_key') == 'UPPER_VALUE'

    conf = Config({'t_1': 1, 't_2': 2, 'x_3': 3, 'x_t': 4})
    assert conf.filter('T')._dict == {'2': 2, '1': 1}


def test_cache_property():
    class Foo:

        @cached_property
        def foo(self):
            nonlocal count
            count += 1
    count = 0
    foo = Foo()
    for i in range(10):
        foo.foo
        assert count == 1


def test_parm_check():
    def param(a1, a2):
        pass
    assert param_check(param, 'a1') is False
    assert param_check(param, 'a1', 'a2') is True
    assert param_check(param, 'a1', limit=1) is True


def test_async_file():
    pass  # TODO


def test_user_file():
    pass  # TODO
