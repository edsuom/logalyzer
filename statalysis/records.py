#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
NAME
statalysis: Analyzes web server log files


SYNOPSIS
sa [--vhost somehost.com]
   [-p] [-e, --exclude code1,code2,...]
   [-d, --ruledir <directory of rule files>]
     [-r, --rules rule1,rule2,...]
     [-u, --ua <file
outFile


DESCRIPTION

Analyzes log files in the directory where outFile is to go, producing
outFile in CSV format.

WARNING: If your bot rules match innocent search engines, e.g., with
'/robots.txt', don't use the list from -i to block access to your web
server!

OPTIONS

--vhost vhost
A particular virtual host of interest

-p, --print
Print records after loading

-e, --exclude exclude
Exclude HTTP code(s) (comma separated list, no spaces)

-d, --ruledir ruledir
Directory for .net, .ua, and .url file(s) containing IP, user-agent,
and url exclusion rules

-n, --net rules
Rules corresponding to .net files in ruledir containing IP network
exclusion rules in aaa.bbb.ccc.ddd/ee notation

-u, --ua rules
Rules corresponding to .ua files containing regular expressions (case
sensitive) that match User-Agent strings to exclude

-b, --url rules
Rules corresponding to .url files containing regular expressions (case
sensitive) that match url strings indicating a malicious bot. All
records from IP addresses with bot behavior will be purged.

--omit
Omit the user-agent string from the records

-s, --shelve file
File in which to save a Python shelf of the records (the CSV file is
still written)

-i, --ip file
File in which to save a list of the (unique) purged IP addresses.

-v, --verbose
Run verbosely


LICENSE
Copyright (C) 2015 Tellectual LLC
"""

import csv

from twisted.internet import reactor

from util import Base
import logread


class RuleReader(Base):
    """
    I read rule files
    """
    def __init__(self, rulesDir, verbose=False):
        self.myDir = rulesDir
        self.verbose = verbose
    
    def linerator(self, filePath):
        self.msg("Reading '{}'...", filePath, '-')
        fh = open(filePath, 'rb')
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.msg("| {}", line)
            yield line
        fh.close()
        
    def rules(self, extension, csvList):
        """
        Supply a file extension and a comma-separated list of rules as a
        string, and I'll read the rules from the corresponding files
        in my rules directory, returning a list of their lines.

        If an empty string or None is supplied, all the corresponding
        rule files in the rules directory will be read.
        """
        def addExtension(x):
            return "{}.{}".format(x, extension)

        lines = []
        nameList = self.csvTextToList(csvList, addExtension)
        if not nameList:
            nameList = [
                x for x in self.filesInDir()
                if x.endswith(".{}".format(extension))]
        for fileName in nameList:
            filePath = self.pathInDir(fileName)
            for line in self.linerator(filePath):
                lines.append(line)
        return lines
        

class Recorder(Base):
    """
    I load records from a Reader and save them in a CSV file
    """
    ruleTable = (
        ('n', "IPMatcher"),
        ('u', "UAMatcher"),
        ('b', "botMatcher"))
    
    def __init__(self, opt):
        self.opt = opt
        self.csvFilePath = opt[0]
        self.logDir = self.dirOfPath(self.csvFilePath)
        
    def readerFactory(self):
        """
        I generate and return a log reader with all its rules loaded per
        your command-line options
        """
        self.verbose = self.opt['v']
        rulesDir = self.opt['d']
        if rulesDir is None:
            rulesDir = self.logDir
        self.msg("Loading rules from '{}'", rulesDir, '-')
        self.msg("Exclusions:")
        exclude = self.cvsTextToList(self.opt['e'], int)
        self.msg("| HTTP Codes: {}", ", ".join(exclude))
        rules = {}
        rr = RuleReader(rulesDir, self.verbose)
        for optKey, extension, matcherName in self.ruleTable:
            rules[matcherName] = rr(extension, self.opt[optKey])
        return logread.Reader(
            self.logDir, rules,
            exclude=exclude, noUA=self.opt['omit'], verbose=self.verbose)

    def _oops(self, failure):
        failure.raiseException()

    def _saveRecords(self, records):
        """
        Callback to save records returned from my reader
        """
        printRecords = self.opt['p']
        keys = sorted(records.keys())
        #cfh = open(self.csvFilePath, 'wb')
        #csvWriter = csv.writer(cfh)
        for dt in keys:
            rowBase = [dt.year, dt.month, dt.day, dt.hour, dt.minute]
            if printRecords:
                print "\n{:4d}-{:02d}-{:02d}, {:02d}:{:02d}".format(*rowBase)
            theseRecords = records[dt]
            for thisRecord in theseRecords:
                if printRecords:
                    itemList = [
                        "{}: {}".format(x, y)
                        for x, y in thisRecord.iteritems()]
                    print ", ".join(itemList)
                #csvWriter.writerow(rowBase + thisRecord)
        #cfh.close()
    
    def load(self, vhost):
        d = self.reader.run(vhost).addCallbacks(self._saveRecords, self._oops)
        d.addCallbacks(lambda _ : reactor.stop(), self._oops)
        return d

    def run(self):
        self.reader = self.readerFactory()
        reactor.callWhenRunning(self.load, self.opt['vhost'])
        reactor.run()


def run():
    import ezopt
    opt = ezopt.Opt(__file__)
    rk = Recorder(opt)
    rk.run()


if __name__ == "__main__":
    run()
