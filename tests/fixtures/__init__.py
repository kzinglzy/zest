#!/usr/bin/env python3
# coding: utf-8
import pytest


@pytest.fixture
def cgi_filed():
    class CGIFiled:
        filename = 'filename'
        name = 'cgi'
        file = object()
        headers = {'k': 'v'}

    class CGIFiledStoreage:
        list = [CGIFiled, CGIFiled]

    return CGIFiledStoreage


@pytest.fixture
def http():
    class Utils:
        header = {
            'Cache_Control': 'no_cache',
            'Content_Encoding': 'gzip',
            'Content-Type': 'text/html; charset=utf-8'
        }
        header_line = 'Connection:keep-alive\r\nHost:pyzest.com'
        b_header_line = header_line.encode('utf-8')
        wsgi_header = {'HTTP_' + k.upper(): v for k, v in header.items()}

    return Utils


# @pytest.fixture
# def config_module(tmpdir):
#     config = tmpdir.mkdir('zest_test_tmp').join('config.py')
#     config.write("""
#         NAME='zest'
#         DESC='async web framework'
#         SITE="pyzest.com"
#         AUTHOR='kzinglzy@gmail.com'
#     """)
#     return config
