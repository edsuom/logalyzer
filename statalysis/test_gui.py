#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import urwid as u
from twisted.internet import defer, reactor

from testbase import *

import gui


def deferToDelay(delay=5):
    d = defer.Deferred()
    reactor.callLater(delay, d.callback, None)
    return d


class Display(object):
    lifetime = 10 # seconds
    
    palette = [('heading', 'default,bold', 'default'),]
    
    def __init__(self, widget):
        eventLoop = u.TwistedEventLoop(reactor, manage_reactor=False)

        @eventLoop.handle_exit
        def possiblyQuit(key):
            if key in ('q', 'Q'):
                raise u.ExitMainLoop()
        
        main = u.WidgetWrap(widget)
        reactor.callLater(self.lifetime, possiblyQuit, 'q')
        self.loop = u.MainLoop(
            main, palette=self.palette, handle_mouse=False,
            unhandled_input=possiblyQuit, event_loop=eventLoop)
        self.loop.start()

    def stop(self):
        self.loop.stop()
        

class TestMessages(TestCase):
    def setUp(self):
        self.m = gui.Messages()
        self.display = Display(self.m)

    def tearDown(self):
        self.display.stop()
    
    def test_justHeading(self):
        self.m.heading("Foo Bar", 1)
        return deferToDelay()
