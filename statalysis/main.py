#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
NAME
statalysis: Analyzes web server log files


SYNOPSIS
sa [-v, --verbose] [--cores N]
   [-p] [-e, --exclude http1,http2,...]
   [-d, --ruledir <directory of rule files>]
     [-i, --ip  [xX]|rule1,rule2,...]
     [-n, --net [xX]|rule1,rule2,...]
     [-u, --ua  [xX]|rule1,rule2,...]
     [-b, --bot [xX]|rule1,rule2,...]
     [-r, --ref [xX]|rule1,rule2,...]
   [-y, --secondary]
   [-s, --save <file to save purged IPs>]
dbURL [logfiles...]


DESCRIPTION

Using the database who RFC-1738 url is supplied as the first (and
possibly only) argument, analyzes the log files listed in further
arguments, or in the director(ies) listed, or in the current
directory if there are no further arguments.

Specify particular ip, net, ua, bot, or ref rules in the rules
directory with a comma-separated list after the -i, -n, -u, -b, or -r
option. Use x or X to skip all such rules. Omit the option to use all
pertinent rules in the rules directory.

All records from IP addresses with bot behavior will be purged.

WARNING: If any of your bot-detecting rules that purge IP addresses
(bot, ref) match innocent search engines, e.g., with a url match to
'/robots.txt', don't use the saved list (--save) to block access to
your web server!


OPTIONS

-e, --exclude exclude
Exclude HTTP code(s) (comma separated list, no spaces)

-d, --ruledir ruledir
Directory for .net, .ua, and .url file(s) containing IP, user-agent, and url exclusion rules (default: ./rules)

-i, --ip rules
Rules corresponding to .ip files in ruledir containing IP addresses aaa.bbb.ccc.ddd notation

-n, --net rules
Rules corresponding to .net files in ruledir containing IP network exclusion rules in aaa.bbb.ccc.ddd/ee notation

-u, --ua rules
Rules corresponding to .ua files containing regular expressions (case sensitive) that match User-Agent strings to exclude

-b, --bot rules
Rules corresponding to .url files containing regular expressions (case sensitive) that match url strings indicating a malicious bot

-r, --referrer rules
Rules corresponding to .ref files containing regular expressions (case sensitive) that match referrer strings indicating a malicious bot

-o, --vhost rules
Rules corresponding to .vhost files containing regular expressions (case sensitive) that match virtual host requests indicating a malicious bot

-y, --secondary
Ignore secondary files (css, webfonts, images)

-t, --timestamp
Compare logfile timestamps to stored versions in the DB and only parse if newer

-s, --save file
File in which to save a list of the purged (or consolidated) IP addresses, in ascending numerical order with repeats omitted.

--cores N
The number of CPU cores (really, python processes) to run in parallel. Set to 0 and the queue will run in a threadpool instead.

-v, --verbose
Run verbosely

--info
Run even more verbosely

-w, --warn
Extreme verbosity, with database transaction info

-g, --gui
Run with console-mode GUI (implies -v, --info, and -w)


LICENSE
Copyright (C) 2015 Tellectual LLC
"""

import os.path

from twisted.internet import reactor, defer

from util import Base #, Args (TODO: Use Args class instead of ezopt)
from writer import IPWriter
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
    I load records from a Reader and update a database with them.

    """
    ruleTable = (
        ('i', "ip",    "IPMatcher"),
        ('n', "net",   "NetMatcher"),
        ('u', "ua",    "UAMatcher"),
        ('b', "url",   "BotMatcher"),
        ('r', "ref",   "RefMatcher"),
        ('o', "vhost", "VhostMatcher"),
    )
    
    def __init__(self, opt):
        self.opt = opt
        self.verbose = opt['v']
        self.triggerID = reactor.addSystemEventTrigger(
            'before', 'shutdown', self.shutdown)

    def shutdown(self):
        """
        There is only one appropriate callback for shutting the program
        down, and this is it. Let the reactor call it automatically
        when you do a reactor.stop().
        """
        if hasattr(self, 'triggerID'):
            reactor.removeSystemEventTrigger(self.triggerID)
            del self.triggerID
        return self.reader.shutdown()
        
    def parseArgs(self):
        args = list(self.opt)
        self.dbURL = args[0]
        # Logfiles specified by command-line args after the db
        # url. Can be logfiles or directories containing logfiles. If
        # none specified, the logfiles in my current directory will be
        # used.
        self.logFiles = []
        pattern = 'access.log'
        for arg in args[1:]:
            self.logFiles.extend(self.filesInDir(path=arg, pattern=pattern))
        if not self.logFiles:
            self.logFiles = self.filesInDir(pattern=pattern)
        if not self.logFiles:
            raise RuntimeError(
                "No logfiles specified or in current directory")

    def loadRules(self):
        """
        Loads rules per your command-line options. Returns a dict of
        sifters loaded with all the selected rules.
        """
        rulesDir = self.opt['d']
        if rulesDir is None:
            rulesDir = os.path.join(self.myDir, 'rules')
        rules = {}
        rr = RuleReader(rulesDir, gui=self.gui, verbose=self.verbose)
        for optKey, extension, matcherName in self.ruleTable:
            theseRules = rr.rules(extension, self.opt[optKey])
            rules[matcherName] = theseRules
        return rules
        
    def readerFactory(self, dbURL):
        """
        I generate and return a log reader with all its rules loaded 
        """
        rules = self.loadRules()
        return logread.Reader(
            rules, dbURL,
            cores=self.opt['cores'],
            exclude=self.csvTextToList(self.opt['e'], int),
            ignoreSecondary=self.opt['y'],
            verbose=self.verbose, info=self.opt['info'],
            warnings=self.opt['w'], gui=self.gui, updateOnly=self.opt['t'])

    def load(self):
        """
        This is where it all happens.
        """
        def done(rejectedIPs):
            filePath = self.opt['s']
            if filePath:
                w = IPWriter()
                w.writeIPs(rejectedIPs, filePath)
            self.msgHeading("Done")
            if self.gui:
                if self.reader.isRunning():
                    self.msgBody("Press 'q' to quit.")
            elif reactor.running:
                reactor.stop()
        # Almost all of my time is spent in this next line
        return self.reader.run(self.logFiles).addCallbacks(done, self.oops)
    
    def run(self):
        self.parseArgs()
        # GUI, if -g option
        if self.opt['g']:
            self.gui = gui.GUI(self.shutdown)
            self.gui.start(self.logFiles)
        # Reader
        self.reader = self.readerFactory(self.opt[0])
        # Everything starts with my load method
        reactor.callWhenRunning(self.load)
        # GO!
        reactor.run()


def run():
    import ezopt
    opt = ezopt.Opt(__file__)
    rk = Recorder(opt)
    rk.run()


if __name__ == "__main__":
    run()
