#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# logalyzer:
# Parses your bloated HTTP access logs to extract the info you want
# about hits to your webserver from (hopefully) real people instead of
# just the endless hackers and bots. Stores the info in a relational
# database where you can access it using all the power of SQL.
#
# Copyright (C) 2015, 2017, 2018 by Edwin A. Suominen,
# http://edsuom.com/logalyzer
#
# See edsuom.com for API documentation as well as information about
# Ed's background and other projects, software and otherwise.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language
# governing permissions and limitations under the License.

NAME = "logalyzer"


### Imports and support
from setuptools import setup

### Define requirements
required = ['sAsync']


### Define setup options
kw = {'version':           "0.4",
      'license':           "Apache License (2.0)",
      'platforms':         "OS Independent",

      'url':               "http://edsuom.com/{}.html".format(NAME),
      'project_urls':      {
          'GitHub':     "https://github.com/edsuom/{}".format(NAME),
          'API':        "http://edsuom.com/{}/{}.html".format(
              NAME, NAME.lower()),
          },
      'author':            "Edwin A. Suominen",
      'author_email':      "foss@edsuom.com",
      'maintainer':        "Edwin A. Suominen",
      'maintainer_email':  "foss@edsuom.com",
      
      'install_requires':  required,
      'packages':          [
          'logalyzer', 'logalyzer.test',
      ],
      'data_files':        [
          ('/opt/logalyzer/rules', ['rules/*']),
          ('/opt/logalyzer/sql', ['sql/*']),
      ],
      'entry_points':      {
          'console_scripts': [
              'la = logalyzer.main:run',
          ],
      },
      'test_suite':        "logalyzer.test",
}

kw['keywords'] = [
    'twisted', 'asynchronous', 'async', 'log', 'logfile',
    'analysis', 'database', 'filtering', 'web', 'access log',
]


kw['classifiers'] = [
    'Development Status :: 4 - Beta',
    'Framework :: Twisted',
    
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    
    'License :: OSI Approved :: Apache Software License',
    
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 2 :: Only',
    'Programming Language :: SQL',

    'Topic :: Database',
    'Topic :: Internet :: Log Analysis',
    'Topic :: System :: Systems Administration',
]

# You get 77 characters. Use them wisely.
kw['description'] =\
"Web server HTTP access log parsing, filtering, and SQL database storage."

kw['long_description'] = """
Parses the bloated HTTP access logs spewed out by your web server to
extract the info you want about hits to your webserver from
(hopefully) real people instead of just the endless hackers and
bots. Stores the info in a relational database where you can access it
using all the power of SQL.

Uses the power of your multicore CPU with Twisted_, AsynQueue_, and
sAsync_ to process log files concurrently and fast. Duplicate entries
are ignored, so you don't need to fret about redundancies in your
logfiles. (It happens.) The filtering goes forwards and backwards;
once an entry has been determined to come from a bad actor, all log
entries from that IP address are purged and ignored.

.. _Twisted: https://twistedmatrix.com/trac/

.. _AsynQueue: http://edsuom.com/AsynQueue.html

.. _sAsync: http://edsuom.com/sAsync.html

If you see bot garbage getting through and polluting your logs with
some new attempt at an exploit, just add a rule for it to your rules
lists, starting with what *logalyzer* comes prepackaged with. The next
time you run it, those entries will get purged as well.

Optionally produces a list of offender IP addresses that you can use
to deny access to your web server entirely.

"""

### Finally, run the setup
setup(name=NAME, **kw)
