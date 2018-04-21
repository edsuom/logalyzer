#!/usr/bin/env python
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
      'package_data':      {
          'mcmandelbrot': [
              'server-install.sh', 'mcm.*', 'blank.jpg'
          ],
      },
      'entry_points':      {
          'console_scripts': [
              'la = logalyzer.main:run',
          ],
      },
      'test_suite':        "asynqueue.test",
}

kw['keywords'] = [
    'twisted', 'asynchronous', 'async', 'threads',
    'parallel', 'distributed',
    'task', 'queue', 'priority', 'multicore', 'fractal',
]


kw['classifiers'] = [
    'Development Status :: 5 - Production/Stable',

    'Intended Audience :: Developers',
    'Intended Audience :: Science/Research',
    
    'License :: OSI Approved :: Apache Software License',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 2 :: Only',
    'Framework :: Twisted',

    'Topic :: System :: Clustering',
    'Topic :: System :: Distributed Computing',
    'Topic :: Software Development :: Object Brokering',
    'Topic :: Software Development :: Libraries :: Python Modules',
]

# You get 77 characters. Use them wisely.
kw['description'] =\
"Asynchronous task queueing with Twisted: threaded, multicore, and remote."

kw['long_description'] = """
Asynchronous task queueing based on the Twisted framework, with task
prioritization and a powerful worker interface. Worker implementations
are included for running tasks asynchronously in the main thread, in
separate threads, in separate Python interpreters (multiprocessing),
and even on separate devices using Twisted's Asynchronouse Message
Protocol.

Includes deferred iteration capability: Calling a task that returns an
iterator can return a Deferator_ instead, which does the iteration in
a Twisted-friendly fashion, even over a network connection. You can
also supply an object conforming to Twisted's IConsumer interface and
iterations will be fed to it as they become available.

Includes an example package mcMandelbrot_ that generates Mandelbrot
set images, row by row, demonstrating the power of asynchronous
multi-core processing. An instance of ProcessQueue_ dispatches the
computations for each row of pixels to workers running on separate
Python processes. The color-mapped RGB results are collected as they
come back and intelligently buffered for iterating in a proper
sequence to a third-party PNG library that wouldn't ordinarily play
nice with Twisted.

Python 3 compatiblity is in the works, but not yet supported.

.. _mcMandelbrot: http://edsuom.com/mcMandelbrot.html

.. _ProcessQueue: http://edsuom.com/AsynQueue/asynqueue.process.ProcessQueue.html

.. _Deferator: http://edsuom.com/AsynQueue/asynqueue.iteration.Deferator.html
"""

### Finally, run the setup
setup(name=NAME, **kw)
