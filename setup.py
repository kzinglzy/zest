#!/usr/bin/env python

import sys
from distutils.core import setup
assert sys.version_info >= (3, 3), NotImplementedError("Python 3.3"
                                                       "or higher is need.")

what_is_zest = open('./README.md', 'r').read()

setup(name='zest',
      version='0.0.1-alpha',
      description='asynchronous and lightweight web framwork of Python',
      long_description=what_is_zest,
      author='kzing',
      author_email='kzinglzy@gmail.com',
      url='http://pyzest.com',
      packages=['zest', 'zest.db', 'zest.ext', 'zest.helper'],
      license='APL',
      platforms='any',
      install_requires=['Mako>=1.0.0'],
      classifiers=[
          "Programming Language :: Python :: 3.4",
          "Development Status :: 3 - Alpha",
          "Environment :: Web Environment",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: Apache Software License",
          "Operating System :: OS Independent",
          "Topic :: Software Development :: Libraries :: Python Modules",
          "Topic :: Text Processing :: Linguistic",
      ]
      )
