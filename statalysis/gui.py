#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import urwid as u


class MessageBox(u.Frame):
    """
    I am a message box consisting of a heading and an expandable space
    for lines you can add under the heading.
    """
    def __init__(self, text):
        header = u.Text(('heading', text))
        self.w = u.SimpleListWalker([])
        body = u.ListBox(self.w)
        super(Message, self).__init__(body, header=header)

    def add(self, text):
        self.w.append(u.Text(text))
                            

class Messages(u.ListBox):
    """
    I provide a place for status messages to be displayed. A heading
    message will be set off from anything above it, and you can supply
    an ID for it. A body message will added below whatever message was
    last supplied, or below the last body message for a particular
    heading ID if you specify an ID and one with that ID was received.
    """
    def __init__(self):
        self.boxes = {}
        body = u.SimpleListWalker([])
        super(Messages, self).__init__(body)
        
    def heading(self, text, ID=None):
        msg = MessageBox(text)
        self.boxes[ID] = msg

    def body(self, text, ID):
        thisBox = self.boxes[ID]
        thisBox.add(text)
        # Do I need to explicitly set focus now?


class Files(u.ListBox):
    """
    I occupy most of the screen with a list of access log files being
    processed.
    """
    def __init__(self):
        self.rows = {}
        self.w = u.SimpleListWalker([])
        super(Files, self).__init__(self.w)

    def setStatus(self, fileName, text):
        row = self.rows.get(fileName, None)
        if row is None:
            statusBox = u.Text("", wrap='clip')
            widgets = [u.Text(fileName), statusBox]
            row = u.Columns([widgets], dividechars=1)
            self.rows[fileName] = row
            self.w.append(row)
        else:
            statusBox = row.contents[1][0]
        statusBox.set_text(text)

    
class GUI(object):
    """
    I am the main curses interface.
    """
    palette = [('heading', 'default,bold', 'default'),]

    def __init__(self, reactor, stopper):
        self.id_counter = 0
        if not callable(stopper):
            raise TypeError(
                "Stopper '{}' is not callable".format(stopper))
        self.stopper = stopper
        self.messages = u.LineBox(Messages())
        self.files = u.LineBox(Files())
        main = u.WidgetWrap(u.Pile([self.messages, self.files]))
        eventLoop = u.TwistedEventLoop(
            reactor, manage_reactor=False)
        self.loop = u.MainLoop(
            main, palette=self.palette, handle_mouse=False,
            unhandled_input=self.possiblyQuit, event_loop=eventLoop)

    def start(self):
        self.loop.start()

    def possiblyQuit(self, key):
        if key in ('q', 'Q'):
            self.stopper()
            self.loop.stop()

        
    def msgHeading(self, text, ID=None):
        if ID is None:
            self.id_counter += 1
            ID = self.id_counter
        self.messages.heading(text, ID)
        return ID

    def msgBody(self, text, ID=None):
        if ID is None:
            ID = self.id_counter
        self.messages.body(text, ID)

    def fileStatus(self, fileName, text):
        self.files.setStatus(fileName, text)

        
