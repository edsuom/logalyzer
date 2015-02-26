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
     [-i, --ip  [xX]|rule1,rule2,...]
     [-n, --net [xX]|rule1,rule2,...]
     [-u, --ua  [xX]|rule1,rule2,...]
     [-b, --bot [xX]|rule1,rule2,...]
     [-r, --ref [xX]|rule1,rule2,...]
   [--omit] [-y, --secondary]
   [-s, --save <file to save purged IPs>]
   [-v, --verbose]
outFile


DESCRIPTION

Analyzes log files in the directory where outFile is to go, producing
outFile in CSV format.

Specify particular ip, net, ua, bot, or ref rules in the rules
directory with a comma-separated list after the -i, -n, -u, -b, or -r
option. Use x or X to skip all such rules. Omit the option to use all
pertinent rules in the rules directory.

All records from IP addresses with bot behavior will be purged.

WARNING: If any of your bot or referrer rules match innocent search
engines, e.g., with '/robots.txt', don't use the list from -i to block
access to your web server!

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

-i, --ip rules
Rules corresponding to .ip files in ruledir containing IP addresses
aaa.bbb.ccc.ddd notation.

-n, --net rules
Rules corresponding to .net files in ruledir containing IP network
exclusion rules in aaa.bbb.ccc.ddd/ee notation.

-u, --ua rules
Rules corresponding to .ua files containing regular expressions (case
sensitive) that match User-Agent strings to exclude.

-b, --bot rules
Rules corresponding to .url files containing regular expressions (case
sensitive) that match url strings indicating a malicious bot.

-r, --referrer rules
Rules corresponding to .ref files containing regular expressions (case
sensitive) that match referrer strings indicating a malicious bot.

--omit
Omit the user-agent string from the records

-y, --secondary
Ignore secondary files (css, webfonts, images)

-s, --save file
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
        self.msg("")
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
        if csvList in ['x', 'X']:
            return []
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

    Look through it with

    less -x5,8,12,16,21,52,69,75,100,200 -S <file.csv>

    """
    csvDelimiter = '\t'
    
    ruleTable = (
        ('i', "ip",  "IPMatcher"),
        ('n', "net", "NetMatcher"),
        ('u', "ua",  "UAMatcher"),
        ('b', "url", "BotMatcher"),
        ('r', "ref", "RefMatcher"))
    
    headings = {
        'vhost': "Virtual Host",
        'ip':    "IP Address",
        'code':  "HTTP",
        'url':   "URL Requested",
        'ref':   "Referrer",
        'ua':    "User Agent",
        }
    
    def __init__(self, opt):
        self.opt = opt
        self.csvFilePath = opt[0]
        self.myDir = self.dirOfPath(self.csvFilePath)
        
    def readerFactory(self):
        """
        I generate and return a log reader with all its rules loaded per
        your command-line options
        """
        self.verbose = self.opt['v']
        rulesDir = self.opt['d']
        if rulesDir is None:
            rulesDir = self.myDir
        self.msg("Loading rules from '{}'", rulesDir, '-')
        self.msg("Exclusions:")
        exclude = self.csvTextToList(self.opt['e'], int)
        self.msg("| HTTP Codes: {}", ", ".join([str(x) for x in exclude]))
        rules = {}
        rr = RuleReader(rulesDir, self.verbose)
        for optKey, extension, matcherName in self.ruleTable:
            rules[matcherName] = rr.rules(extension, self.opt[optKey])
        return logread.Reader(
            self.myDir, rules,
            vhost=self.opt['vhost'],
            exclude=exclude, noUA=self.opt['omit'],
            ignoreSecondary=self.opt['y'],
            verbose=self.verbose)

    def _oops(self, failure):
        failure.raiseException()

    def _saveRecords(self, rk):
        """
        Callback to save records returned from my reader
        """
        def makeRow(x):
            row = []
            if 'vhost' in fields:
                row.append(x['vhost'])
            for field in ('ip', 'code', 'url', 'ref'):
                row.append(x[field])
            if 'ua' in fields:
                row.append(x['ua'])
            return row
        
        def writeRow(x):
            row = makeRow(x)
            csvWriter.writerow(rowBase + row)

        # Save the IP addresses if that option set
        if self.opt['i']:
            fh = open(self.opt['i'], 'w')
            for ip in sorted(rk.ipList):
                fh.write(ip + '\n')
            fh.close()
        # Now the actual records
        records = rk.records
        printRecords = self.opt['p']
        keys = sorted(records.keys())
        cfh = open(self.csvFilePath, 'wb')
        csvWriter = csv.writer(cfh, delimiter=self.csvDelimiter)
        rowBase = ["Year", "Mo", "Day", "Hr", "Min"]
        fields = records[keys[0]][0]
        writeRow(self.headings)
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
                writeRow(thisRecord)
        cfh.close()
    
    def load(self):
        d = self.reader.run().addCallbacks(self._saveRecords, self._oops)
        d.addCallbacks(lambda _ : reactor.stop(), self._oops)
        return d

    def run(self):
        self.reader = self.readerFactory()
        reactor.callWhenRunning(self.load)
        reactor.run()


def run():
    import ezopt
    opt = ezopt.Opt(__file__)
    rk = Recorder(opt)
    rk.run()


if __name__ == "__main__":
    run()
