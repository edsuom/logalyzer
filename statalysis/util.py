#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os, os.path
from collections import deque


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
        thisCache = deque([], self.N)
        self.caches.append(thisCache)
        k = len(self.caches) - 1
        if name is None:
            name = str(k)
        self.names.append(name)
        return k
    
    def clear(self, value=None):
        for cache in self.caches:
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

    def set(self, k, x, getOldest=False):
        """
        Appends x to cache k, which will result in it being found there if
        checked within N cache misses.

        The value least recently added (from a cache miss) will be
        popped off the other end. It isn't strictly an LRU cache,
        since a cache hit will be drowned in misses.

        If C{getOldest} is set C{True}, the oldest value that was
        popped off (if one was) will be returned. If nothing was
        popped off or the keyword is not set, the result will be
        C{None}.
        """
        k = self._checkIndex(k)
        c = self.caches[k]
        if getOldest and len(c) > self.N:
            result = c.pop()
        else:
            result = None
        c.appendleft(x)
        return result


class Base(object):
    """
    Subclass me to have a few convenient methods and easily work with
    a directory. The default directory is the current one, set another
    with the 'myDir' attribute.
    """
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

    def dtFormat(self, dt):
        return "{:4d}-{:02d}-{:02d}+{:02d}:{:02d}".format(
            dt.year, dt.month, dt.day,
            dt.hour, dt.minute)
        
    def msg(self, proto, *args):
        if self.verbose:
            if args and args[-1].startswith('-'):
                args = list(args[:-1]) + ["-"*70]
                proto += "\n{}"
            print proto.format(*args)

    def oops(self, failure):
        failure.printDetailedTraceback()
        
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
    
