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
Utility functions, base classes, and the L{Args} class.
"""

import re, os, os.path
from collections import deque
from contextlib import contextmanager

from twisted.internet import reactor, defer


def rdb(sep, *args):
    """
    Builds a regular expression for separated digits.
    """
    parts = []
    for numDigits in args:
        parts.append(r'(\d{{{:d}}})'.format(numDigits))
    return sep.join(parts)

def rc(*parts):
    """
    Compiles a regular expression from whitespace-separated parts.
    """
    rexp = r'\s+'.join(parts) + r'\s*$'
    return re.compile(rexp)


def profile(f, *args, **kw):
    def done(result):
        with open('theseus.out', 'wb') as fh:
            t.write_data(fh)
        t.uninstall()
        pr.disable()
        import pstats
        with open('profile.out', 'wb') as fh:
            ps = pstats.Stats(pr, stream=fh).sort_stats('cumulative')
            ps.print_stats()
        return result
    
    def substituteFunction(*args, **kw):
        d = f(*args, **kw)
        d.addCallback(done)
        return d

    from cProfile import Profile
    pr = Profile()
    pr.enable()
    from theseus import Tracer
    t = Tracer(); t.install()
    substituteFunction.func_name = f.func_name
    return substituteFunction


class DatabaseError(Exception):
    """
    Incompatible database.
    """


class CacheManager(object):
    """
    Let me manage a cache or two for you.
    """
    def __init__(self, N=40):
        self.N = N
        self.names = []
    
    def new(self, name=None):
        """
        Generates the FIFO queue for a new sort-of LRU cache and returns
        its index, starting with 0 for the first cache.
        """
        if not hasattr(self, 'caches'):
            self.caches = []
        thisCache = deque()
        self.caches.append(thisCache)
        k = len(self.caches) - 1
        if name is None:
            name = str(k)
        self.names.append(name)
        return k
    
    def clear(self, k=None, value=None):
        """
        Clears all caches (or just the specified one) of all values (or
        just the specified value).
        """
        if k is not None:
            kk = self._checkIndex(k)
        for j, cache in enumerate(self.caches):
            if k is None or j == kk:
                if value is None:
                    cache.clear()
                while cache.count(value):
                    cache.remove(value)

    def _checkIndex(self, k):
        if not isinstance(k, int):
            k = self.names.index(k)
        if k < 0 or k >= len(self.names):
            raise IndexError("Invalid cache index {:d}".format(k))
        return k
    
    def check(self, k, x):
        """
        Checks cache k for the string x, returning True if it's there or
        False if not.
        """
        k = self._checkIndex(k)
        return bool(self.caches[k].count(x))

    def set(self, k, x):
        """
        Appends x to cache k, which will result in it being found there if
        checked within N cache misses.

        The value least recently added (from a cache miss) will be
        popped off the other end and returned, unless it happens to
        equal the value just added. (This lets you use it to prune
        another list somewhere.) Mine isn't strictly an LRU cache,
        since a cache hit will get drowned in misses.

        If nothing was popped off because the cache hasn't yet grown
        to N elements yet, or the new value equals the popped-off one,
        the result will be C{None}.
        """
        k = self._checkIndex(k)
        c = self.caches[k]
        if len(c) >= self.N:
            result = c.pop()
            if result == x:
                result = None
        else:
            result = None
        c.appendleft(x)
        return result


class BogusQueue(object):
    def __init__(self, **kw):
        if kw.pop('useThreading', False):
            self.threadPool = reactor.getThreadPool()
        else:
            self.threadPool = None
        for name, value in kw.iteritems():
            setattr(self, name, value)
            
    def call(self, fName, *args, **kw):
        """
        Threading stuff copied from
        twisted.internet.threads.deferToThreadPool
        """
        def done(success, result):
            if success:
                reactor.callFromThread(d.callback, result)
            else:
                reactor.callFromThread(d.errback, result)
        
        f = getattr(self, fName)
        if self.threadPool:
            d = defer.Deferred()
            self.threadPool.callInThreadWithCallback(
                done, f, *args)
            return d
        return defer.succeed(f(*args))

    def shutdown(self):
        if self.threadPool:
            self.threadPool.stop()
        return defer.suceed(None)

    
class Base(object):
    """
    Subclass me to have a few convenient methods and easily work with
    a directory. The default directory is the current one, set another
    with the 'myDir' attribute.

    I look at my I{gui} and I{verbose} attributes to decide what to
    show users from your calls to L{msgHeading} and L{msgBody}.

    """
    gui = None
    verbose = False

    @classmethod
    def linger(cls, setting=None):
        if setting is not None:
            cls._pleaseLinger = setting
        return getattr(cls, '_pleaseLinger', False)
    
    @property
    def myDir(self):
        return getattr(self, '_myDir', os.curdir)

    @myDir.setter
    def myDir(self, value):
        if not os.path.exists(value):
            os.mkdir(value)
        self._myDir = value

    @myDir.deleter
    def myDir(self):
        del self._myDir

    @staticmethod
    def dtFormat(dt):
        return "{:4d}-{:02d}-{:02d}+{:02d}:{:02d}".format(
            dt.year, dt.month, dt.day,
            dt.hour, dt.minute)

    @staticmethod
    def deferToDelay(delay):
        d = defer.Deferred()
        reactor.callLater(delay, d.callback, None)
        return d
    
    def msgHeading(self, proto, *args):
        """
        Sends a new message heading to the GUI or console, returning a
        integer that is unique to the caller's instance of me and that
        will be the ID for the next L{msgBody} call(s) from this
        instance.
        """
        if self.gui:
            self._headingID = self.gui.msgHeading(proto, *args)
            return self._headingID
        if self.verbose:
            proto = "\n" + proto
            args = list(args) + ["-"*70]
            proto += "\n{}"
            print proto.format(*args)

    def msgBody(self, proto, *args, **kw):
        """
        Send a new line of message body to the last heading for this
        instance, or the instance whose ID is specified via the
        keyword C{ID}.
        """
        if self.gui:
            # The get/if structure lets you explicitly specify ID=None
            ID = kw.get('ID', None)
            if ID is None:
                ID = self._headingID
            self.gui.msgBody(ID, proto, *args)
        elif self.verbose:
            print proto.format(*args)

    def msgOrphan(self, proto, *args):
        if self.gui:
            self.gui.msgOrphan(proto, *args)
        elif self.verbose:
            print proto.format(*args)
            
    def msgWarning(self, proto, *args):
        if self.gui:
            self.gui.warning(proto, *args)
            self.linger(True)
        elif self.verbose:
            print "WARNING: "+proto.format(*args)

    def msgError(self, proto, *args):
        if self.gui:
            self.gui.error(proto, *args)
            self.linger(True)
            return self.deferToDelay(10)
        print "ERROR: "+proto.format(*args)
                
    def msgProgress(self, ID=None, N=1):
        if not self.gui:
            return
        if ID is None:
            ID = self._headingID
        self.gui.msgProgress(ID, N)
            
    def fileStatus(self, fileName, *args):
        if self.gui:
            self.gui.fileStatus(fileName, *args)
        elif self.verbose and args:
            proto = "FILE {}: {}".format(fileName, args[0])
            print proto.format(*args[1:])
    
    def fileProgress(self, fileName):
        if self.gui:
            self.gui.fileStatus(fileName)

    def oops(self, failure, *args):
        text = "In {},".format(repr(self))
        if args:
            textProto = "{} {},".format(text, args[0])
            text = textProto.format(*args[1:])
        text += "\n {}".format(failure.getTraceback())
        self.msgError(text)
    
    def csvTextToList(self, text, converter):
        if text:
            return [converter(x.strip()) for x in text.split(',')]
        return []

    @staticmethod
    def checkPath(filePath):
        if not os.path.isfile(filePath):
            raise ValueError("No file '{}' found".format(filePath))
    
    @staticmethod
    def dirOfPath(filePath):
        return os.path.dirname(os.path.abspath(filePath))

    def filesInDir(self, path=None, pattern=None):
        """
        Returns a list of names (not paths) of files in my instance's
        directory I{myDir}, or the directory specified. If the
        "directory" is actually a file, returns a single-item list
        with just that filename.

        If you specify a pattern string, only files containing the
        pattern will be included.
        """
        if path is None:
            path = self.myDir
        if os.path.isfile(path):
            fileList = [path]
        else:
            fileList = os.listdir(path)
        if pattern is None:
            return fileList
        results = []
        for fileName in fileList:
            if pattern in fileName:
                results.append(fileName)
        return results
    
    def pathInDir(self, fileName):
        """
        Returns the absolute path of a file in my directory
        """
        path = os.path.abspath(os.path.join(self.myDir, fileName))
        self.checkPath(path)
        return path

    _checkLeakStuff = []
    def cleak(self, f, *args, **kw):
        """
        For debugging memory leaks. Calls the deferred-returning function
        f (with any args, kw), recording changes made to the heap
        during the call. Prints a warning-level message about the heap
        every call, and stops with the debugger after 'stopInterval'
        calls, if defined.

        Returns a deferred that fires with the call result, which
        should make this indistinguishable from the original call.
        """
        def done(result):
            k = self._checkLeakStuff[0]
            if not hasattr(self, 'msgInterval') or k % self.msgInterval == 0:
                hpd = self._checkLeakStuff[1].heap()
                print "\n"
                self.msgWarning("Heap after {:d} intervals:\n{}", k, hpd)
                self.msgWarning("Heap (byrcs):\n{}", hpd.byrcs)
                # Particular focus
                for kk in xrange(2):
                    self.msgWarning(
                        "Heap (byrcs[{:d}].byvia):\n{}",
                        kk, hpd.byrcs[kk].byvia)
            if hasattr(self, 'stopInterval') and k >= self.stopInterval:
                import pdb
                pdb.set_trace()
            return result
        
        if not self._checkLeakStuff:
            from guppy import hpy
            self._checkLeakStuff.extend([0, hpy()])
            self._checkLeakStuff[1].setrelheap()
        self._checkLeakStuff[0] += 1
        return f(*args, **kw).addCallback(done)

    def gleak(self, f, *args, **kw):
        import gc
        gc.set_debug(gc.DEBUG_LEAK)
    

class Args(object):
    """
    Convenience class by Edwin A. Suominen for compact and sensible
    commandline argument parsing. The code of this class, separate
    from the rest of this module and package, is dedicated to the
    public domain.

    Usage: Construct an instance with a text description of your
    application. Then call the instance for each option you want to
    add, with a short letter (just a single letter) preceded by a
    single hyphen ("-"), a long option preceded by a pair of hyphens
    ("--"), a default value if the option isn't just C{store_true},
    and a text description of the option. There will be a total of 3-4
    arguments.

    You will access the option value using the short letter value,
    which gives you 26 possibilities for options (52 if you use both
    upper and lowercase). If you need more than that, you may be
    overcomplicating your command line.

    Call the instance with just one argument, a text description, to
    allow for positional arguments. The arguments will be accessed
    from the instance as sequence items.

    The instance will look exactly like an L{argparse.ArgumentParser}
    object, all set up and ready to have its attributes accessed.
    """
    def __init__(self, text):
        self.args = None
        import argparse
        self.parser = argparse.ArgumentParser(description=text)

    def __nonzero__(self):
        return any([
            bool(getattr(self.args, x))
            for x in dir(self.args) if not x.startswith('_')])

    def addDefault(self, text, default, dest=None):
        if dest and '{}' in text: text = text.format(dest)
        if "default" not in text.lower():
            text += " [{}]".format(default)
        return text
    
    def __call__(self, *args):
        if len(args) == 4:
            shortArg, longArg, default, helpText = args
            dest = shortArg[1:]
            helpText = self.addDefault(helpText, default, dest)
            self.parser.add_argument(
                shortArg, longArg, dest=dest, default=default,
                action='store', type=type(default), help=helpText)
            return
        if len(args) == 3:
            shortArg, longArg, helpText = args
            self.parser.add_argument(
                shortArg, longArg, dest=shortArg[1:],
                action='store_true', help=helpText)
            return
        if len(args) == 1:
            helpText = args[0]
            self.parser.add_argument(
                '_args_', default=None, nargs='*', help=helpText)
            return

    def __iter__(self):
        for x in getattr(self, '_args_', []):
            yield x

    def __len__(self):
        return len(getattr(self, '_args_', []))

    def __getitem__(self, k):
        return getattr(self, '_args_', [])[k]
    
    def __getattr__(self, name):
        if self.args is None:
            self.args = self.parser.parse_args()
        return getattr(self.args, name, None)
