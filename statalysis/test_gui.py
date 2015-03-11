#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

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
    'foo.txt', 'bar.txt', 'really-cool-file.txt',
    'lotsa-files.html', 'more-and-more.md']


def deferToDelay(delay=5):
    d = defer.Deferred()
    reactor.callLater(delay, d.callback, None)
    return d


class Display(object):
    lifetime = 10 # seconds
    
    def __init__(self, widget):
        def possiblyQuit(key):
            if key in ('q', 'Q'):
                reactor.stop()

        main = u.WidgetWrap(u.LineBox(widget))
        eventLoop = u.TwistedEventLoop(reactor, manage_reactor=False)
        self.screen = Screen()
        self.screen.register_palette(gui.GUI.palette)
        self.screen.set_terminal_properties(
            colors=16,
            bright_is_bold=True)
        self.loop = u.MainLoop(
            main, screen=self.screen,
            unhandled_input=possiblyQuit,
            event_loop=eventLoop)
        reactor.addSystemEventTrigger('before', 'shutdown', self.stop)
        self.loop.start()

    def update(self):
        self.loop.draw_screen()

    def stop(self):
        self.screen.unhook_event_loop(self.loop)
        self.loop.stop()

        
class TestCase(tb.TestCase):
    def setUp(self):
        if hasattr(self, 'wInstance'):
            self.w = self.wInstance()
        else:
            self.w = self.wClass(*getattr(self, 'wArgs', []))
        self.display = Display(self.w)

    def tearDown(self):
        self.display.stop()
        
    def showBriefly(self, delay=0.5):
        self.display.update()
        return deferToDelay(delay)


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
    wClass = gui.FileRow
    wArgs = ['access.log', 20]

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
        self.f = gui.Files(FILENAMES)

    def test_setStatus(self):
        fileName = "foo.txt"
        self.f.setStatus(fileName, "Some message with an int {:d}!", 50)
        row = self.f.contents[0][0]
        statusText = row.status
        self.assertEqual(
            statusText.get_text()[0],
            "Some message with an int 50!")
        
            
class TestFiles(TestCase):
    def wInstance(self):
        self.f = gui.Files(FILENAMES)
        return u.Filler(self.f, valign='bottom')
    
    @defer.inlineCallbacks
    def test_update(self):
        for step in xrange(200):
            fileName = random.choice(FILENAMES)
            if random.randint(0,20) == 1:
                self.f.setStatus(fileName, "Done at step {:d}!", step)
            else:
                self.f.indicator(fileName)
            yield self.showBriefly(0.05)
        yield self.showBriefly(2.0)
            

class TestGUI(TestCase):
    def setUp(self):
        self.display = gui.GUI(FILENAMES)
        
    @defer.inlineCallbacks
    def test_update(self):
        for step in xrange(200):
            fileName = random.choice(FILENAMES)
            if random.randint(0,20) == 1:
                self.display.fileStatus(fileName, "Done at step {:d}!", step)
            else:
                self.display.fileStatus(fileName)
            yield self.showBriefly(0.05)
        yield self.showBriefly(2.0)

        
                
