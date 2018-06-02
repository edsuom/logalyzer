#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# logalyzer:
# Parses your bloated HTTP access logs to extract the info you want
# about hits to your webserver from (hopefully) real people instead of
# just the endless hackers and bots. Stores the info in a relational
# database where you can access it using all the power of SQL.
#
# Copyright (C) 2015, 2017, 2018 by Edwin A. Suominen,
# http://edsuom.com/logalyzer
#
# See edsuom.com for API documentation as well as information about
# Ed's background and other projects, software and otherwise.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language
# governing permissions and limitations under the License.

import random

import urwid as u
from urwid.raw_display import Screen

from twisted.internet import defer, reactor

import testbase as tb

import gui


LINES = """
Once there was a man from Devrizes
who had balls of two different sizes.
The one was so small
it was no ball at all.
But the other won several prizes.
""".strip().split('\n')

FILENAMES = [
    'TEST-INFO',
    'foo.txt', 'bar.txt', 'whatever.py', 'xyz.html',
    'really-cool-file.txt', 'lotsa-files.html',
    'more-and-more.md', 'cant_get_enough.log']


def deferToDelay(delay=5):
    d = defer.Deferred()
    reactor.callLater(delay, d.callback, None)
    return d


class Display(object):
    lifetime = 5 # seconds
    
    def __init__(self, palette=None):
        # A screen is useful to have right away
        self.screen = Screen()
        if palette is None:
            palette = gui.GUI.palette
        self.screen.register_palette(palette)

    def setWidget(self, widget, useFiller=False):
        def possiblyQuit(key):
            if key in ('q', 'Q'):
                reactor.stop()

        # The widget under test is outline, possibly padded with filler
        outlined = u.LineBox(widget)
        if useFiller:
            height = 'flow' if hasattr(widget, 'rows') else 3
            w = u.Filler(outlined, valign='top', height=height)
        else:
            w = outlined
        main = u.WidgetWrap(w)
        # The loops
        eventLoop = u.TwistedEventLoop(reactor, manage_reactor=False)
        self.loop = u.MainLoop(
            main, screen=self.screen,
            unhandled_input=possiblyQuit,
            event_loop=eventLoop)
        self.loop.start()

    def width(self):
        return self.screen.get_cols_rows()[0] - 2
        
    def update(self):
        self.loop.draw_screen()

    def stop(self):
        self.screen.unhook_event_loop(self.loop)
        self.loop.stop()

        
class TestCase(tb.TestCase):
    palette = None
    
    def setUp(self):
        self.display = Display(self.palette)
        if hasattr(self, 'wInstance'):
            self.w = self.wInstance()
        else:
            self.w = self.wClass(*getattr(self, 'wArgs', []))
        self.display.setWidget(
            self.w, useFiller=getattr(self, 'useFiller', False))
    
    def tearDown(self):
        self.display.stop()
        
    def showBriefly(self, delay=0.5):
        self.display.update()
        return deferToDelay(delay)


class TestPalette(TestCase):
    palette = []
    _colorNames = [
        'black', 'dark red', 'dark green', 'brown', 'dark blue',
        'dark magenta', 'dark cyan', 'light gray', 'dark gray',
        'light red', 'light green', 'yellow', 'light blue',
        'light magenta', 'light cyan', 'white']
    for _name in _colorNames:
        for _settingSuffix in ("", "bold", "underline"):
            palette.append((
                "_".join(_name.split() + [_settingSuffix]).strip('_'),
                ",".join([_name, _settingSuffix]).strip(','),
                'default'))
    
    wClass = gui.MessageBox
    wArgs = ["Console color test"]
    alphabet = " abcedefghijklmnopqrstuvwxyz"

    def test_colors(self):
        for name in [x[0] for x in self.palette]:
            self.w.body.append(u.Text((name, name + self.alphabet)))
        return self.showBriefly(5)
    

class TestMessageBox(TestCase):
    wClass = gui.MessageBox
    wArgs = ["This is a heading!"]

    @defer.inlineCallbacks
    def test_add(self):
        yield self.showBriefly()
        for line in LINES:
            self.w.add(line)
            yield self.showBriefly()

    @defer.inlineCallbacks
    def test_toggleCurrent(self):
        for k in xrange(5):
            isCurrent = bool(k % 2)
            if isCurrent:
                line = "Current, emphasize!"
            else:
                line = "Not current, pay no attention."
            self.w.add(line)
            self.w.setCurrent(isCurrent)
            yield self.showBriefly(1.0)

    @defer.inlineCallbacks
    def test_progress(self):
        self.w.add("The next line is a progress indicator")
        for k in xrange(20):
            self.w.progress()
            yield self.showBriefly(0.1)
            
        
class TestMessages(TestCase):
    wClass = gui.Messages

    @defer.inlineCallbacks
    def test_justOne(self):
        self.w.heading("First Heading", 1)
        yield self.showBriefly()
        for line in LINES:
            self.w.msg(line, 1)
            yield self.showBriefly(1)
        yield self.showBriefly(10)

    @defer.inlineCallbacks
    def test_several(self):
        for k in xrange(1,6):
            self.w.heading("Heading #{:d}".format(k), k)
            yield self.showBriefly()
            for line in LINES:
                self.w.msg(line, k)
                yield self.showBriefly(0.2)

    @defer.inlineCallbacks
    def test_updateHeadings(self):
        IDs = ['Alpha', 'Bravo', 'Charlie', 'Delta']
        for ID in IDs:
            self.w.heading("Heading {}".format(ID), ID)
            yield self.showBriefly(0.1)
        for k in xrange(20):
            ID = random.choice(IDs)
            line = random.choice(LINES)
            self.w.msg(line, ID)
            yield self.showBriefly(0.2)


class TestMessagesWithFiller(TestCase):
    def wInstance(self):
        self.m = gui.Messages()
        return u.Pile([
            self.m, (2, u.SolidFill('/'))])

    @defer.inlineCallbacks
    def test_fits(self):
        rows = self.display.screen.get_cols_rows()[1]
        self.w.contents[1] = (self.w.contents[1][0], ('given', rows/2))
        for k in xrange(1,3):
            self.m.heading("Heading #{:d}".format(k), k)
            for line in LINES:
                self.m.msg(line, k)
                yield self.showBriefly(0.1)
        yield self.showBriefly(1.0)

    @defer.inlineCallbacks
    def test_dynamicResizing(self):
        rowsBefore = 0
        for step in xrange(100):
            rows = self.display.screen.get_cols_rows()[1]
            if rows != rowsBefore:
                self.w.contents[1] = (
                    self.w.contents[1][0], ('given', rows/2))
                self.m.heading(
                    "Changed from {:d} to {:d} rows".format(
                        rowsBefore, rows), step)
                rowsBefore = rows
                self.m.msg("Adjust window size to see another update", step)
            yield self.showBriefly(0.1)


class TestFileRow(TestCase):
    useFiller = True
    wClass = gui.FileRow
    wArgs = ['access.log', 20, 50]

    @defer.inlineCallbacks
    def test_step(self):
        for step in xrange(20):
            self.w.step()
            yield self.showBriefly(0.05)
        self.w.done()
        yield self.showBriefly()

    def test_status(self):
        self.w.setStatus("What a fine status we have!")
        return self.showBriefly(2)


class TestFilesAPI(tb.TestCase):
    def setUp(self):
        self.f = gui.Files(FILENAMES[1:], 100)

    def test_setStatus(self):
        fileName = "foo.txt"
        self.f.setStatus(fileName, "Some message with an int {:d}!", 50)
        row = self.f.contents[0][0]
        self.assertEqual(
            row.status.get_text()[0],
            "Some message with an int 50!")

    def test_cellWidth(self):
        self.f.leftColWidth = 10
        width, nCols = self.f._cellWidth(100)
        self.assertEqual(nCols, 2)
        self.assertGreater(width, 45)
        width, nCols = self.f._cellWidth(120)
        self.assertEqual(nCols, 2)
        self.assertGreater(width, 55)
        width, nCols = self.f._cellWidth(140)
        self.assertEqual(nCols, 3)
        self.assertGreater(width, 45)

            
class TestFiles(TestCase):
    useFiller = True
    def wInstance(self):
        self.totalWidth = self.display.width() - 2
        return gui.Files(FILENAMES, self.totalWidth)
    
    @defer.inlineCallbacks
    def test_update(self):
        fileName = FILENAMES[0]
        width, nCols = self.w._cellWidth(self.totalWidth)
        self.w.setStatus(fileName, "{:d} cols {:d} chars wide", nCols, width)
        for step in xrange(200):
            fileName = random.choice(FILENAMES[1:])
            if random.randint(0,20) == 1:
                self.w.setStatus(fileName, "Done at step {:d}!", step)
            else:
                self.w.indicator(fileName)
            yield self.showBriefly(0.05)
        yield self.showBriefly(2.0)
            

class TestGUI(TestCase):
    def setUp(self):
        self.display = gui.GUI()
        self.display.start(FILENAMES)
        
    @defer.inlineCallbacks
    def test_update(self):
        ID = self.display.msgHeading("The mother of all messages!")
        for step in xrange(200):
            fileName = random.choice(FILENAMES[1:])
            if random.randint(0,20) == 1:
                self.display.fileStatus(
                    fileName, "Done at step {:d}!", step)
            else:
                self.display.fileStatus(fileName)
            if random.randint(0,5) == 1:
                ID = self.display.msgHeading(
                    "A new heading at step {:d}!", step)
            if random.randint(0,5) == 1:
                self.display.msgBody(
                    ID, "Body stuff, step {:d}...", step)
            elif random.randint(0,5) == 1:
                self.display.msgOrphan("An orphan message at step {:d}", step)
            elif random.randint(0,15) == 1:
                self.display.warning(
                    "A warning message at step {:d}", step)
            yield self.showBriefly(0.1)
        yield self.showBriefly(2.0)

        
                
