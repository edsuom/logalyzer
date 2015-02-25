#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
NAME
statalysis: Analyzes web server log files


SYNOPSIS
sa [--vhost somehost.com] outFile


DESCRIPTION

Analyzes log files in the directory where outFile is to go, producing
outFile in CSV format.


OPTIONS

--vhost vhost
A particular virtual host of interest

-p, --print
Print records after loading

-e, --exclude exclude
Exclude HTTP code(s) (comma separated list, no spaces)

-d, --ruledir ruledir
Directory for file(s) containing IP exclusion rules

-r, --rules rules
Rules corresponding to .txt files in ruledir containing IP exclusion rules in
aaa.bbb.ccc.ddd/ee notation

-u, --ua file
File containing regular expressions (case sensitive) that match
User-Agent strings to exclude

-b, --bot file
File containing regular expressions (case sensitive) that match url
strings indicating a bot. All records from IP with bot behavior will
be omitted.

--omit
Omit the user-agent string from the records

-v, --verbose
Run verbosely


LICENSE
Copyright (C) 2015 Tellectual LLC
"""

import os.path, csv

from twisted.internet import reactor

import logread


class Recorder(object):
    """
    I load records from a Reader and save them in a CSV file
    """
    def __init__(self, opt):
        self.opt = opt
        self.csvFilePath = opt[0]
        self.logDir = os.path.dirname(os.path.abspath(self.csvFilePath))

    def textToList(self, text, converter):
        if text:
            return [converter(x.strip()) for x in text.split(',')]
        return []
        
    def readerFactory(self):
        ruleDir = self.opt['d']
        verbose = self.opt['v']
        if ruleDir:
            print "Rules: ",
            ruleFiles = []
            for rule in self.textToList(self.opt['r'], lambda x: x+'.txt'):
                rulePath = os.path.join(ruleDir, rule)
                if not os.path.isfile(rulePath):
                    raise ValueError(
                        "Rule file '{}' not found".format(rulePath))
                ruleFiles.append(rulePath)
                print rule,
        exclude = self.textToList(self.opt['e'], int)
        print "Exclusions: ", exclude
        return logread.Reader(
            self.logDir,
            exclude=exclude,
            noUA=self.opt['omit'],
            ruleFiles=ruleFiles,
            uaFile=self.opt['u'],
            urlFile=self.opt['b'],
            verbose=self.opt['v'])

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
