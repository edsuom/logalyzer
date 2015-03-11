#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
NAME
statalysis: Analyzes web server log files


SYNOPSIS
sa [--vhost somehost.com]
   [-p] [-e, --exclude http1,http2,...]
   [-d, --ruledir <directory of rule files>]
     [-i, --ip  [xX]|rule1,rule2,...]
     [-n, --net [xX]|rule1,rule2,...]
     [-u, --ua  [xX]|rule1,rule2,...]
     [-b, --bot [xX]|rule1,rule2,...]
     [-r, --ref [xX]|rule1,rule2,...]
   [--omit] [-y, --secondary]
   [-s, --save <file to save purged IPs>]
   [-v, --verbose]
<file> <file...>


DESCRIPTION

Analyzes log files in the directory where outFile is to go, producing
one or more output <files> (except if -c option set).

The format of the output files is determined by their extension:

.csv: Comma-separated (actually tabs) values, one row for each record
.pyo: Marshalled lists, read back by iterating marshal.load(fh)

Specify particular ip, net, ua, bot, or ref rules in the rules
directory with a comma-separated list after the -i, -n, -u, -b, or -r
option. Use x or X to skip all such rules. Omit the option to use all
pertinent rules in the rules directory.

All records from IP addresses with bot behavior will be purged.

WARNING: If any of your bot-detecting rules that purge IP addresses
(bot, ref) match innocent search engines, e.g., with a url match to
'/robots.txt', don't use the saved list (--save) to block access to
your web server!

You can skim through the CSV file with:

less -x5,8,12,16,21,52,69,75,110,200 -S <file.csv>


OPTIONS

--vhost vhost
A particular virtual host of interest

-p, --print
Print records after loading

--db dburl
Specify the RFC-1738 url of a database for the records and it will be
updated as the logfiles are parsed.

-e, --exclude exclude
Exclude HTTP code(s) (comma separated list, no spaces)

-d, --ruledir ruledir
Directory for .net, .ua, and .url file(s) containing IP, user-agent,
and url exclusion rules

-i, --ip rules
Rules corresponding to .ip files in ruledir containing IP addresses
aaa.bbb.ccc.ddd notation

-n, --net rules
Rules corresponding to .net files in ruledir containing IP network
exclusion rules in aaa.bbb.ccc.ddd/ee notation

-u, --ua rules
Rules corresponding to .ua files containing regular expressions (case
sensitive) that match User-Agent strings to exclude

-b, --bot rules
Rules corresponding to .url files containing regular expressions (case
sensitive) that match url strings indicating a malicious bot

-r, --referrer rules
Rules corresponding to .ref files containing regular expressions (case
sensitive) that match referrer strings indicating a malicious bot

-y, --secondary
Ignore secondary files (css, webfonts, images)

-s, --save file
File in which to save a list of the purged (or consolidated) IP
addresses, in ascending numerical order with repeats omitted.

-c, --consolidate
Just consolidate IP addresses in the <file> with those in the ip rules
(-i), saving that to the file specified with -s. Ignores logfiles and
net, ua, bot, and ref rules, and doesn't generate any csv file

--cores N
The number of CPU cores (really, python processes) to run in parallel

-v, --verbose
Run verbosely

--info
Provide info about IP records being purged

-w, --warn
Provide database transaction info

-g, --gui
Run with console-mode GUI (implies -v, --info, and -w)


LICENSE
Copyright (C) 2015 Tellectual LLC
"""

from twisted.internet import reactor

from util import Base
from writer import Writer
import logread, gui


class RuleReader(Base):
    """
    I read rule files
    """
    def __init__(self, rulesDir='rules', gui=None, verbose=False):
        self.myDir = rulesDir
        self.gui = gui
        self.verbose = verbose
    
    def linerator(self, filePath):
        N = 0
        self.msgHeading("Reading '{}'...", filePath)
        fh = open(filePath, 'rb')
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            N += 1
            yield line
        self.msgBody("{:d} rules", N)
        fh.close()

    def lines(self, filePath):
        """
        Just returns a list of non-commented, non-blank lines from the
        specified filePath
        """
        return list(self.linerator(filePath))
        
    def rules(self, extension, text):
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
        if text in ['x', 'X']:
            return lines
        nameList = self.csvTextToList(text, addExtension)
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
    ruleTable = (
        ('i', "ip",  "IPMatcher"),
        ('n', "net", "NetMatcher"),
        ('u', "ua",  "UAMatcher"),
        ('b', "url", "BotMatcher"),
        ('r', "ref", "RefMatcher"))
    
    def __init__(self, opt):
        self.opt = opt
        self.verbose = opt['v']
        self.csvFilePath = opt[0]
        self.myDir = self.dirOfPath(self.csvFilePath)

    def loadRules(self, consolidate=False):
        """
        Loads rules per your command-line options. If I am in consolidate
        mode, just returns a list of the ip addresses from the
        selected ip rules. Otherwise returns a dict of sifters loaded
        with all the selected rules.
        """
        rulesDir = self.opt['d']
        if rulesDir is None:
            rulesDir = self.myDir
        rules = {}
        rr = RuleReader(rulesDir, gui=self.gui, verbose=self.verbose)
        for optKey, extension, matcherName in self.ruleTable:
            theseRules = rr.rules(extension, self.opt[optKey])
            rules[matcherName] = theseRules
            if consolidate and extension == 'ip':
                # All we do in consolidate mode is read the ip
                # rules.
                return theseRules
        return rules
        
    def readerFactory(self):
        """
        I generate and return a log reader with all its rules loaded 
        """
        return logread.Reader(
            self.myDir,
            dbURL=self.opt['db'],
            cores=self.opt['cores'],
            verbose=self.verbose, info=self.opt['info'],
            warnings=self.opt['w'], gui=self.gui)

    def _doneReading(self, stuff):
        """
        Callback to process an ipList and records returned from my reader.
        """
        ipList, records = stuff
        # Save the IP addresses from purges if that option set
        filePath = self.opt['s']
        if filePath:
            self.w.writeIPs(ipList, filePath)
        # Now write the actual records, returning the deferred from
        # the writer
        return self.w.write(records)
        
    def load(self):
        """
        This is where it all happens.
        """
        def allDone(null):
            self.msgHeading("All Done!")
            if self.gui:
                self.msgBody("Press 'q' to quit.")
            else:
                reactor.stop()

        d = self.reader.run(
            self.loadRules(),
            vhost=self.opt['vhost'],
            exclude=self.csvTextToList(self.opt['e'], int),
            ignoreSecondary=self.opt['y'])
        d.addCallbacks(self._doneReading, self.oops)
        d.addCallbacks(allDone, self.oops)
        return d

    def consolidate(self, outPath):
        """
        Consolidates dotted-quad addresses from selected ip rules with the
        ones in my command-line filePath(s).
        """
        ipList = self.loadRules(consolidate=True)
        rr = RuleReader()
        for filePath in self.opt:
            ipList.extend(rr.lines(filePath))
        self.w.writeIPs(ipList, outPath)
    
    def run(self):
        if self.opt['c']:
            outPath = self.opt['s']
            self.consolidate(outPath)
            return
        if self.opt['g']:
            self.gui = gui.GUI()
        self.reader = self.readerFactory()
        if self.gui:
            self.gui.start(self.reader.fileNames)
        reactor.callWhenRunning(self.load)
        kw = {'printRecords': self.opt['p'], 'gui': self.gui}
        self.w = Writer(*list(self.opt), **kw)
        reactor.run()


def run():
    import ezopt
    opt = ezopt.Opt(__file__)
    rk = Recorder(opt)
    rk.run()


if __name__ == "__main__":
    run()
