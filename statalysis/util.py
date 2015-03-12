#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os, os.path
from collections import deque

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


class ProcessError(Exception):
    pass

class DeferredException(Exception):
    pass


class CacheManager(object):
    """
    Let me manage a cache or two for you.
    """
    def __init__(self, N=40):
        self.N = N
        self.names = []
    
    def new(self, name=None):
        """
        Generates the FIFO queue for a new sort-of LRU cache of strings
        and returns its index, starting with 0 for the first cache.
        """
        if not hasattr(self, 'caches'):
            self.caches = []
        thisCache = deque([])
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

    @property
    def myDir(self):
        return getattr(self, '_myDir', os.curdir)

    @myDir.setter
    def myDir(self, value):
        if not os.path.isdir(value):
            raise OSError("Directory '{}' not found".format(value))
        self._myDir = value

    @myDir.deleter
    def myDir(self):
        del self._myDir

    @staticmethod
    def dtFormat(dt):
        return "{:4d}-{:02d}-{:02d}+{:02d}:{:02d}".format(
            dt.year, dt.month, dt.day,
            dt.hour, dt.minute)
    
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
        elif self.verbose:
            print "WARNING: "+proto.format(*args)

    def msgProgress(self, ID=None):
        if not self.gui:
            return
        if ID is None:
            ID = self._headingID
        self.gui.msgProgress(ID)
            
    def fileStatus(self, fileName, *args):
        if self.gui:
            self.gui.fileStatus(fileName, *args)
        elif self.verbose:
            proto = "File {}: " + args[0]
            args = [fileName] + list(args[1:])
            print proto.format(*args)

    def fileProgress(self, fileName):
        if self.gui:
            self.gui.fileStatus(fileName)

    def oops(self, failure, *args):
        text = "In {},".format(repr(self))
        if args:
            textProto = "{} {},".format(text, args[0])
            text = textProto.format(*args[1:])
        text += "\n {}".format(failure.getTraceback())
        if self.gui:
            self.gui.error(text)
        else:
            from twisted.internet import reactor
            if reactor.running:
                try:
                    reactor.stop()
                except:
                    pass
            self.msgHeading("ERROR: {}", text)
    
    def csvTextToList(self, text, converter):
        if text:
            return [converter(x.strip()) for x in text.split(',')]
        return []

    def dirOfPath(self, filePath):
        return os.path.dirname(os.path.abspath(filePath))

    def filesInDir(self):
        """
        Lists names (not paths) of files in my directory
        """
        return os.listdir(self.myDir)

    def checkPath(self, filePath):
        if not os.path.isfile(filePath):
            raise ValueError("No file '{}' found".format(filePath))
                               
    def pathInDir(self, fileName):
        """
        Returns the absolute path of a file in my directory
        """
        if os.path.split(fileName)[0]:
            raise ValueError(
                "Path '{}' specified, use file name only".format(fileName))
        path = os.path.abspath(os.path.join(self.myDir, fileName))
        self.checkPath(path)
        return path
    
