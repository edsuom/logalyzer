#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# logalyzer:
# Parses your bloated HTTP access logs to extract the info you want
# about hits from (hopefully) real people instead of just the endless
# stream of hackers and bots that passes for web traffic
# nowadays. Stores the info in a relational database where you can
# access it using all the power of SQL.
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


"""
Mock objects and an improved TestCase for statalysis
"""

import re, sys, os.path, shutil, inspect, logging, atexit
from datetime import datetime as dt

from zope.interface import implements
from twisted.internet import reactor, defer
from twisted.python.failure import Failure
from twisted.internet.interfaces import IConsumer
from twisted.trial import unittest

from asynqueue import info, TaskQueue
from asynqueue.interfaces import IWorker


VERBOSE = False


RULES_IP = """
64.79.100.21
192.95.29.116
62.210.141.227
69.64.46.145 
189.232.100.179
82.80.249.169
118.194.247.128
74.101.43.243
176.8.90.172
134.249.51.137
195.242.218.133
216.137.107.220
24.10.60.163
134.249.76.28
130.211.119.22
65.207.23.201
72.9.226.168
198.64.149.137
144.76.70.133
176.8.91.201
134.249.49.191
""".split('\n')


RULES_NET = """
2.72.0.0/13
2.92.0.0/14
2.132.0.0/14
5.34.56.0/22
5.60.0.0/16
5.101.152.0/21
5.143.0.0/16
5.158.96.0/19
5.158.232.0/21
5.166.0.0/15
5.248.0.0/16
5.254.96.0/21
5.255.192.0/18
31.6.70.0/23
31.11.43.0/24
31.11.128.0/17
31.15.88.0/21
31.23.0.0/16
31.28.224.0/19
31.29.0.0/19
31.31.96.0/19
31.43.128.0/19
31.129.96.0/19
31.131.0.0/17
31.162.64.0/18
31.170.168.0/21
31.174.0.0/15
31.178.0.0/16
31.181.0.0/16
31.184.224.0/21
31.184.234.0/23
31.184.236.0/22
31.187.0.0/18
31.192.104.0/21
31.192.128.0/19
31.207.192.0/18
37.9.0.0/19
37.9.32.0/20
37.9.48.0/21
37.17.176.0/21
37.44.64.0/18
37.45.0.0/16
37.52.0.0/14
37.56.0.0/15
37.99.0.0/17
37.110.128.0/19
37.115.0.0/16
37.128.0.0/17
37.139.0.0/18
37.140.0.0/16
37.143.8.0/21
37.143.16.0/20
37.143.88.0/21
37.143.96.0/21
37.143.104.0/21
37.144.0.0/14
37.150.0.0/15
37.212.0.0/14
37.221.128.0/19
37.221.160.0/21
37.228.64.0/21
37.228.80.0/20
37.229.0.0/16
46.0.0.0/16
46.4.240.0/27
46.10.0.0/16
46.16.240.0/21
46.17.96.0/21
46.28.101.0/24
46.30.160.0/21
46.33.224.0/19
46.36.217.0/24
46.38.96.0/19
46.39.0.0/18
46.39.64.0/19
46.50.128.0/18
46.53.141.0/24
46.56.128.0/17
46.61.0.0/16
46.62.0.0/15
46.72.0.0/15
46.98.0.0/16
46.108.0.0/16
46.109.0.0/16
46.112.0.0/15
46.118.0.0/15
46.147.128.0/17
46.148.48.0/20
46.151.152.0/21
46.158.0.0/16
46.159.0.0/16
46.160.80.0/21
46.164.0.0/18
46.164.128.0/18
46.164.192.0/18
46.172.0.0/16
46.173.0.0/17
46.173.128.0/19
46.173.160.0/19
46.175.200.0/21
46.180.0.0/15
46.182.48.0/21
46.185.0.0/17
46.187.0.0/17
46.191.128.0/18
46.200.0.0/14
46.211.0.0/16
46.229.176.0/20
46.237.0.0/17
46.254.18.0/23
62.16.96.0/19
62.21.0.0/17
62.24.64.0/19
62.64.64.0/18
62.69.0.0/19
62.76.0.0/16
62.85.0.0/17
62.109.0.0/20
62.117.64.0/18
62.122.64.0/21
62.122.104.0/21
62.129.192.0/18
62.133.128.0/19
62.140.224.0/19
62.141.64.0/18
62.148.64.0/19
62.152.32.0/19
62.168.0.0/18
62.168.224.0/19
62.182.104.0/21
62.213.32.0/19
62.213.64.0/18
62.220.32.0/19
62.221.64.0/19
62.233.142.0/26
62.244.0.0/18
69.175.104.218
70.85.189.224/29
77.28.0.0/15
77.34.0.0/15
77.37.128.0/17
77.40.0.0/17
77.41.0.0/17
77.43.128.0/17
77.45.128.0/17
77.46.128.0/17
77.51.0.0/18
77.51.64.0/18
77.55.0.0/16
77.65.0.0/17
77.70.0.0/17
77.73.128.0/21
77.75.8.0/21
77.78.10.0/23
77.79.128.0/18
77.79.192.0/18
77.81.0.0/24
77.85.0.0/16
77.87.32.0/20
77.87.152.0/21
77.87.168.0/21
77.87.192.0/21
77.88.0.0/18
77.91.128.0/18
77.91.224.0/21
77.93.0.0/18
77.93.32.0/19
77.94.124.0/22
77.94.192.0/19
77.106.64.0/18
77.108.192.0/18
77.120.0.0/14
77.221.128.0/19
77.222.32.0/19
77.222.128.0/19
77.232.156.0/22
77.233.160.0/19
77.234.0.0/19
77.234.192.0/19
77.235.96.0/20
77.239.224.0/19
77.241.160.0/20
77.243.96.0/22
77.244.208.0/20
77.247.208.0/22
77.252.0.0/14
78.8.0.0/14
109.171.0.0/17
109.173.0.0/17
109.184.0.0/16
109.185.0.0/16
109.187.0.0/16
109.188.0.0/16
109.191.0.0/16
109.194.0.0/18
109.194.64.0/19
109.195.48.0/20
109.196.16.0/20
109.196.128.0/20
109.200.96.0/19
109.200.128.0/19
109.206.96.0/19
109.207.200.0/21
109.227.64.0/18
109.229.0.0/19
109.230.0.0/18
109.230.128.0/19
109.243.0.0/16
109.252.0.0/16
109.254.0.0/16
128.72.0.0/15
""".split('\n')

RULES_UA = """
[bB]ot[^a-zA-Z]
_bot$
Yahoo
[cC]rawler
[sS]pider
[sS]ite[eE]xplorer
Deepnet
[fF]etcher
Media[pP]artners
yandex
archiver
panscient
ips-agent
Voyager
findlink
heritrix
[fF]acebook[eE]xternal[hH]it
Analyzer
ichiro
coccoc
binlar
A6-Indexer
Google-SearchByImage
FlipboardProxy
Java/
wget
curl
libwww
yandex
baidu
""".split('\n')

RULES_BOT = """
fckeditor
/\w+\.php
^/js/.+\.js
/tiny_mce/
/etc/passwd
/scripts/
logitec\.se
/account/
//components/
/trackback/?$
""".split('\n')

dt1 = dt(2015, 2, 20, 12, 2, 49)
dt2 = dt(2015, 3, 2, 21, 17, 16)
dt3 = dt(2015, 3, 2, 21, 17, 17)

ip1 = "171.127.9.141"
ip2 = "32.132.214.244"

RECORDS = {
    dt1: [
        {'vhost': "foo.com",
         'ip': ip1, 'http': 200, 'was_rd': False,
         'url': "/", 'ref': "-", 'ua': "-"},
        {'vhost': "foo.com",
         'ip': ip1, 'http': 200, 'was_rd': False,
         'url': "/image.png", 'ref': "-", 'ua': "-"}],
    dt2: [
        {'vhost': "bar.com",
         'ip': ip2, 'http': 404, 'was_rd': False,
         'url': "/", 'ref': "-", 'ua': "-"}],
}

VALUES = (
    [ip1, 200, False, 1, 1, 1, 1],
    [ip1, 200, False, 1, 2, 1, 1],
    [ip2, 200, False, 1, 1, 2, 1],
)

months = ["2", "2", "3"]
vhosts = ["foo.com", "foo.com", "bar.com"]
ips = [ip1, ip1, ip2]


class Bogus:
    pass

def moduleDir(absolute=False, parent=False):
    modulePath = inspect.getfile(Bogus)
    if absolute or parent:
        modulePath = os.path.abspath(modulePath)
    if parent:
        modulePath = os.path.dirname(modulePath)
    return os.path.dirname(modulePath)

def fileInModuleDir(fileNameOrPath, absolute=False):
    return os.path.normpath(
        os.path.join(moduleDir(absolute), fileNameOrPath))

def deleteIfExists(fileNameOrPath):
    def tryDelete(fp):
        if os.path.exists(fp):
            os.remove(fp)
            return True
        return False
    if not tryDelete(fileNameOrPath):
        tryDelete(fileInModuleDir(fileNameOrPath))

def disappearingCopy(srcFile, dstFile):
    srcPath = fileInModuleDir(srcFile)
    dstPath = fileInModuleDir(dstFile)
    shutil.copyfile(srcPath, dstPath)
    atexit.register(deleteIfExists, dstPath)
    return dstPath

def tempFiles(*args):
    for fileName in args:
        atexit.register(deleteIfExists, fileName)
    return args

def deferToDelay(delay):
    d = defer.Deferred()
    reactor.callLater(delay, d.callback, None)
    return d
    

class MsgBase(object):
    """
    A mixin for providing a convenient message method.
    """
    def isVerbose(self):
        if hasattr(self, 'verbose'):
            return self.verbose
        if 'VERBOSE' in globals():
            return VERBOSE
        return False

    def msg(self, proto, *args):
        if self.isVerbose():
            if not hasattr(self, 'msgAlready'):
                proto = "\n" + proto
                self.msgAlready = True
            if args and args[-1] == "-":
                args = args[:-1]
                proto += "\n{}".format("-"*40)
            print proto.format(*args)

    
class Runerator(object):
    """
    Iterates over an executable object to see if it worked and do
    something if it did before its output is cleaned up.
    """
    def __init__(self, testcase, executable, *args, **kw):
        self.testcase = testcase
        self.executable = executable
        self.args = args
        self.kw = kw

    def run(self, fileName):
        self.producedFile = fileInModuleDir(fileName)
        if os.path.exists(self.producedFile):
            os.remove(self.producedFile)
        return self.executable(*self.args, **self.kw)

    def fail(self):
        self.testcase.fail(
            "No file '{}' was produced.".format(self.producedFile))

    def beforeFile(self, fileName):
        """
        Here is the use case::
          for result in r.beforeFile('foo.pdf'):
              <do something before checking for and deleting produced>
              <file 'filePath'>
          <file is now deleted>

        """
        yield self.run(fileName)
        if os.path.exists(self.producedFile):
            os.remove(self.producedFile)
        else:
            self.fail()

    def afterFile(self, fileName):
        """
        Here is the use case::
          for filePath in r.afterFile('foo.pdf'):
              <do something with produced file 'filePath'>
          <file is now deleted>

        """
        self.run(fileName)
        if os.path.exists(self.producedFile):
            yield self.producedFile
            os.remove(self.producedFile)
        else:
            self.fail()

    def producesFileAndResult(self, fileName):
        """
        Here is the use case::
          for filePath, result in r.producesFile('foo.pdf'):
              <do something with produced file 'filePath'>
          <file is now deleted>

        """
        result = self.run(fileName)
        if os.path.exists(self.producedFile):
            yield self.producedFile, result
            os.remove(self.producedFile)
        else:
            self.fail()


class TestHandler(MsgBase, logging.StreamHandler):
    def __init__(self, verbose=False):
        logging.StreamHandler.__init__(self)
        self.verbose = verbose
        self.records = []
        self.setFormatter(logging.Formatter(
            '%(levelname)s: %(message)s'))
        
    def emit(self, record):
        self.records.append(record)
        if self.verbose:
            return logging.StreamHandler.emit(self, record)


class MockDTK(MsgBase):
    def __init__(self, verbose):
        self.verbose = verbose
        self.dtList = []
        self.callsMade = []
        self._pending = True

    def isPending(self, *args):
        if args:
            self._pending = args[0]
        return self._pending

    def _noteCall(self, name, dt):
        self.msg("DTK: {}({})", name, dt)
        self.callsMade.append([name, dt])
    
    def check(self, dt):
        self._noteCall('check', dt)
        return dt in self.dtList

    def set(self, dt):
        self._noteCall('set', dt)
        if dt not in self.dtList:
            self.dtList.append(dt)
        

class MockWorker(MsgBase):
    implements(IWorker)

    def __init__(self, verbose=False, runDelay=0.02):
        if verbose:
            self.verbose = True
        self.runDelay = runDelay
        self.ran = []
        self.isShutdown = False
    
    def _reallyRun(self):
        f, args, kw = self.task.callTuple
        result = f(*args, **kw)
        self.ran.append(self.task)
        with self.verboseContext():
            ID = getattr(self, 'ID', 0)
            self.msg("Worker {} ran {} = {}", ID, str(self.task), result)
        self.task.d.callback(result)

    def run(self, task):
        def ran(result, d):
            d.callback(None)
            return result
        
        self.task = task
        reactor.callLater(self.runDelay, self._reallyRun)
        d = defer.Deferred()
        task.d.addCallback(ran, d)
        return d
        
    def stop(self):
        self.isShutdown = True
        self.msg("Shutting down worker {}", self)
        d = getattr(getattr(self, 'task', None), 'd', None)
        if d is None or d.called:
            d_shutdown = defer.succeed(None)
        else:
            d_shutdown = defer.Deferred()
            d.chainDeferred(d_shutdown)
        return d_shutdown

    def crash(self):
        pass
            

class IterationConsumer(MsgBase):
    implements(IConsumer)

    def __init__(self, verbose=False, writeTime=None):
        self.verbose = verbose
        self.writeTime = writeTime
        self.producer = None

    def registerProducer(self, producer, streaming):
        if self.producer:
            raise RuntimeError()
        self.producer = producer
        producer.registerConsumer(self)
        self.data = []
        self.msg(
            "Registered with producer {}. Streaming: {}",
            repr(producer), repr(streaming))

    def unregisterProducer(self):
        self.producer = None
        self.msg("Producer unregistered")

    def write(self, data):
        def resume(null):
            if self.producer:
                self.producer.resumeProducing()
        
        self.data.append(data)
        self.msg(
            "Data received from {}: '{}'", repr(self.producer), str(data))
        if self.writeTime:
            self.producer.pauseProducing()
            self.d = deferToDelay(
                self.writeTime).addCallback(resume)


class TestCase(MsgBase, unittest.TestCase):
    """
    Slightly improved TestCase
    """
    # Nothing should take longer than 10 seconds, and often problems
    # aren't apparent until the timeout stops the test.
    timeout = 10
    
    def oops(self, failureObj, *metaArgs):
        if self.isVerbose():
            if not metaArgs:
                metaArgs = (repr(self),)
            text = info.Info().setCall(*metaArgs).aboutFailure(failureObj)
            self.msg(text)
        return failureObj
    
    def doCleanups(self):
        if hasattr(self, 'msgAlready'):
            del self.msgAlready
        return super(TestCase, self).doCleanups()

    def multiplerator(self, N, expected):
        def check(null):
            self.assertEqual(resultList, expected)
            del self.d
        
        dList = []
        resultList = []
        for k in xrange(N):
            yield k
            self.d.addCallback(resultList.append)
            dList.append(self.d)
        self.dm = defer.DeferredList(dList).addCallback(check)
            
    def checkOccurrences(self, pattern, text, number):
        occurrences = len(re.findall(pattern, text))
        if occurrences != number:
            info = \
                u"Expected {:d} occurrences, not {:d}, " +\
                u"of '{}' in\n-----\n{}\n-----\n"
            info = info.format(number, occurrences, pattern, text)
            self.assertEqual(occurrences, number, info)
    
    def checkBegins(self, pattern, text):
        pattern = r"^\s*%s" % (pattern,)
        self.assertTrue(bool(re.match(pattern, text)))

    def checkProducesFile(self, fileName, executable, *args, **kw):
        producedFile = fileInModuleDir(fileName)
        if os.path.exists(producedFile):
            os.remove(producedFile)
        result = executable(*args, **kw)
        self.assertTrue(
            os.path.exists(producedFile),
            "No file '{}' was produced.".format(
                producedFile))
        os.remove(producedFile)
        return result

    def runerator(self, executable, *args, **kw):
        return Runerator(self, executable, *args, **kw)

    def assertPattern(self, pattern, text):
        proto = "Pattern '{}' not in '{}'"
        if '\n' not in pattern:
            text = re.sub(r'\s*\n\s*', '', text)
        if isinstance(text, unicode):
            # What a pain unicode is...
            proto = unicode(proto)
        self.assertTrue(
            bool(re.search(pattern, text)),
            proto.format(pattern, text))

    def assertStringsEqual(self, a, b, msg=""):
        N_seg = 20
        def segment(x):
            k0 = max([0, k-N_seg])
            k1 = min([k+N_seg, len(x)])
            return "{}-!{}!-{}".format(x[k0:k], x[k], x[k+1:k1])
        for k, char in enumerate(a):
            if char != b[k]:
                s1 = segment(a)
                s2 = segment(b)
                msg += "\nFrom #1: '{}'\nFrom #2: '{}'".format(s1, s2)
                self.fail(msg)

    def assertIsFailure(self, x):
        self.assertIsInstance(x, Failure)
        
    def assertNone(self, obj, msg=""):
        if obj is not None:
            if msg:
                msg = "\n" + msg
            self.fail("Expected <None>, got '{}' {}".str(obj, msg))

    def assertNotNone(self, obj, msg=""):
        if obj is None:
            self.fail(msg)

    def assertRecord(self, obj, **kw):
        self.assertIsInstance(obj, tuple, "Not a record, not even a tuple")
        self.assertIsInstance(obj[0], dt, "First element not a datetime")
        self.assertIsInstance(obj[1], dict, "Second element not a dict")
        self.assertIn('http', obj[1])
        self.assertTrue(len(obj[1]) > 5)
        for name, value in kw.iteritems():
            self.assertEqual(obj[1][name], value)
                              
