#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os, os.path


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
    
    def msg(self, proto, *args):
        if self.verbose:
            if args and args[-1].startswith('-'):
                args = list(args[:-1]) + ["-"*70]
                proto += "\n{}"
            print proto.format(*args)

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
    
