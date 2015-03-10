#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import urwid as u


class MessageBox(u.ListBox):
    """
    I am a message box consisting of a heading and an expandable space
    for lines you can add under the heading.
    """
    def __init__(self, text):
        self.hText = text
        body = u.SimpleListWalker([self.headingText(True)])
        super(MessageBox, self).__init__(body)

    def headingText(self, isCurrent):
        attrName = "heading"
        if isCurrent:
            attrName += "_current"
        return u.Text((attrName, self.hText))

    def setCurrent(self, yes):
        self.body[0] = self.headingText(yes)
        if yes:
            self.body.set_focus(0)        
    
    def add(self, text):
        self.body.append(u.Text(text))
        self.setCurrent(True)
        return len(self.body)
                            

class Messages(u.ListBox):
    """
    I provide a place for status messages to be displayed below headings.

    A heading will be set off from anything above it, and provides an
    anchor for messages. Each message will be appended below the
    heading with its ID.

    """
    defaultHeight = 3
    
    def __init__(self):
        self.boxes = []
        body = u.SimpleListWalker([])
        super(Messages, self).__init__(body)

    def adapt(self, w, height=None):
        if height is None:
            height = self.defaultHeight
        return u.BoxAdapter(w, height)
        
    def heading(self, text, ID):
        if ID in self.boxes:
            raise IndexError("ID '{}' already exists".format(ID))
        if len(self.boxes):
            text = "\n" + text
        self.boxes.append(ID)
        msgBox = self.adapt(MessageBox(text))
        self.body.append(msgBox)

    def msg(self, text, ID):
        if ID not in self.boxes:
            raise IndexError(
                "No heading for ID '{}'".format(ID))
        k = self.boxes.index(ID)
        # De-emphasize any other boxes
        for kk, msgBox in enumerate(self.body):
            if kk != k:
                msgBox.setCurrent(False)
        # Add the message line under the heading
        newHeight = self.body[k].add(text)
        if newHeight > self.defaultHeight:
            rawBox = self.body[k].original_widget
            self.body[k] = self.adapt(rawBox, newHeight)
        # Set focus to this last-updated message
        self.body.set_focus(k)


class Files(u.Pile):
    """
    I occupy most of the screen with a list of access log files being
    processed.
    """
    gutterWidth = 2
    
    def __init__(self, fileNames):
        self.fileNames = fileNames
        self.leftColWidth = max([len(x) for x in fileNames])
        widgetList = [(1, self._makeRow(x)) for x in fileNames]
        super(Files, self).__init__(widgetList)

    def _statusBox(self, text):
        return u.Text("", wrap='clip')
        
    def _makeRow(self, fileName):
        widgetList = [
            (self.leftColWidth, u.Text(fileName, align='right')),
            self._statusBox("")]
        return u.Columns(widgetList, dividechars=self.gutterWidth)
        
    def setStatus(self, fileName, text):
        if fileName not in self.fileNames:
            raise IndexError("Unknown filename '{}'".format(fileName))
        k = self.fileNames.index(fileName)
        rowWidget = self.contents[k][0]
        rowWidget[1].set_text(text)

    
class GUI(object):
    """
    I am the main curses interface.
    """
    palette = [
        # Name
        # 'fg color,setting', 'background color', 'mono setting'
        ('heading',
         'dark cyan', 'default', 'bold'),
        ('heading_current',
         'yellow,bold', 'default', 'bold'),
    ]

    def __init__(self, fileNames):
        self.id_counter = 0
        self.m = Messages()
        self.f = Files(fileNames)
        self.pile = u.Pile([
            self.m, u.Divider('=', 1, 1), (len(fileNames), self.f)])
        main = u.WidgetWrap(u.LineBox(self.pile))
        eventLoop = u.TwistedEventLoop(reactor, manage_reactor=False)
        self.screen = Screen()
        self.screen.register_palette(self.palette)
        self.screen.set_terminal_properties(
            colors=16,
            bright_is_bold=True)
        self.loop = u.MainLoop(
            main, screen=self.screen,
            unhandled_input=self.possiblyQuit, event_loop=eventLoop)
        reactor.addSystemEventTrigger('before', 'shutdown', self.stop)
        self.loop.start()

    def update(self):
        self.loop.draw_screen()

    def stop(self):
        self.screen.unhook_event_loop(self.loop)
        self.loop.stop()

    def possiblyQuit(self, key):
        if key in ('q', 'Q'):
            reactor.stop()
    
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

        
