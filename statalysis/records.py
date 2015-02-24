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
    def __init__(self, csvFilePath, printRecords=False, exclude=[]):
        self.csvFilePath = csvFilePath
        self.printRecords = printRecords
        logDir = os.path.dirname(os.path.abspath(csvFilePath))
        self.reader = logread.Reader(logDir)

    def oops(self, failure):
        failure.raiseException()

    def saveRecords(self, records):
        keys = sorted(records.keys())
        cfh = open(self.csvFilePath, 'wb')
        csvWriter = csv.writer(cfh)
        for dt in keys:
            rowBase = [dt.year, dt.month, dt.day, dt.hour, dt.minute]
            if self.printRecords:
                print "\n{:4d}-{:02d}-{:02d}, {:02d}:{:02d}".format(*rowBase)
            theseRecords = records[dt]
            for thisRecord in theseRecords:
                if self.printRecords:
                    print ", ".join([str(x) for x in thisRecord])
                csvWriter.writerow(rowBase + thisRecord)
        cfh.close()
    
    def load(self, vhost):
        d = self.reader.run(vhost).addCallbacks(self.saveRecords, self.oops)
        d.addCallbacks(lambda _ : reactor.stop(), self.oops)
        return d

    def run(self, vhost=None):
        reactor.callWhenRunning(self.load, vhost)
        reactor.run()


def run():
    import ezopt
    opts = ezopt.Opt(__file__)
    exclude = opts['e']
    if exclude:
        exclude = [int(x.strip()) for x in exclude.split(',')]
    else:
        exclude = []
    rk = Recorder(opts[0], printRecords=opts['p'], exclude=exclude)
    rk.run(opts['vhost'])


if __name__ == "__main__":
    run()
