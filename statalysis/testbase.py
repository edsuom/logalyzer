#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!


import re, os, os.path, shutil, inspect, atexit

from twisted.trial import unittest


VERBOSE = True

RULES_IP = """
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
""".split('\n')

RULES_BOT = """
fckeditor
/\w+\.php
/tiny_mce/
/etc/passwd
/scripts/
logitec\.se
/account/
//components/
""".split('\n')


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

    def assertNone(self, obj, msg=""):
        if obj is not None:
            self.fail(msg)

    def assertNotNone(self, obj, msg=""):
        if obj is None:
            self.fail(msg)
            
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

