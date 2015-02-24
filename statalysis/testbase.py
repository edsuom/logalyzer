#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!


import re, os, os.path, shutil, inspect, atexit

from twisted.trial import unittest


VERBOSE = True

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


class TF(object):
    """
    with TF('foo.txt') as filePath:
        <do something to make file, knowing it will be removed after>

    The filePath is a path of the file in my module directory.

    If you supply a second name, the first file will be copied to the
    second, and only the second will be removed after:

    with TF('src.txt', 'dst.txt') as filePath:
       <do something with provided copy 'dst.txt' of 'src.txt',
       knowing 'dst.txt' will be removed after>

    You can also specify a regular expression and replacement string
    in the 2-tuple reMatchReplace and the new file will have that
    replacement done on its contents.

    """
    def __init__(self, fileNameOrPath, dstName=None, reMatchReplace=None):
        self.mDir = moduleDir()
        self.filePath = os.path.normpath(
            os.path.join(self.mDir, fileNameOrPath))
        self.dstName = dstName
        self.reMatchReplace = reMatchReplace

    def __call__(self):
        return self.filePath

    def copyWithReplacement(self, src, dst):
        regex, sub = self.reMatchReplace
        fhSrc = open(src, 'r')
        fhDst = open(dst, 'w')
        for line in fhSrc:
            newLine = re.sub(regex, sub, line)
            if newLine.strip() or not line.strip():
                fhDst.write(newLine)
        fhSrc.close()
        fhDst.close()
    
    def __enter__(self):
        if self.dstName:
            dstFile = os.path.join(self.mDir, self.dstName)
            if self.reMatchReplace:
                self.copyWithReplacement(self.filePath, dstFile)
            else:
                shutil.copyfile(self.filePath, dstFile)
            self.filePath = dstFile
            return dstFile
        self.delete()
        return self.filePath

    def __exit__(self, *args):
        self.delete()
            
    def delete(self):
        if os.path.exists(self.filePath):
            os.remove(self.filePath)
            

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


class TestCase(unittest.TestCase):
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

