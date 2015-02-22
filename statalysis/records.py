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


LICENSE
Copyright (C) 2015 Tellectual LLC


"""

import os.path, csv

from twisted.internet import reactor

import logread


class RecordKeeper(object):
    """
    """
    def __init__(self, csvFilePath, printRecords=False):
        self.csvFilePath = csvFilePath
        self.printRecords = printRecords
        logDir = os.path.dirname(os.path.abspath(csvFilePath))
        self.reader = logread.Reader(logDir)

    def oops(self, failure):
        failure.raiseException()

    def load(self, vhost):
        def gotRecords(records):
            if self.printRecords:
                print records
            with open(self.csvFilePath, 'wb') as cfh:
                csvWriter = csv.writer(cfh)
                for record in records:
                    csvWriter.writerow(record)
            reactor.stop()
        
        return self.reader.run(vhost).addCallbacks(gotRecords, self.oops)

    def run(self, vhost=None):
        reactor.callWhenRunning(self.load, vhost)
        reactor.run()


def run():
    import ezopt
    opts = ezopt.Opt(__file__)
    rk = RecordKeeper(opts[0], printRecords=opts['p'])
    rk.run(opts['vhost'])


if __name__ == "__main__":
    run()
