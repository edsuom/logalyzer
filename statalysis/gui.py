#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import urwid


class Main(urwid.WidgetWrap):
    """
    I am the main curses interface.
    """
    self.header = Messages()
    self.body = FileListBox()
    
    
    
    def msgHeading(self, text):
        pass

    def msgBody(self, text):
        pass
        


class Messages(urwid.Text):
    """
    I provide a place for status messages to be displayed
    """
    def __init__(self, rows):
        super(Messages, self).__init__(align='left', wrap='clip')
        self.newHeight(rows)

    def newLines(self, *lines):
        self.lines.append(line)
        while len(self.lines) > self.rows:
            self.lines.pop(0)
        self.updateText()
        
    def newHeading(self, text):
        # TODO: Header formatting
        self.newLines("", text)

    def newBody(self, text):
        self.newLines(text)

    def newHeight(self, rows):
        self.rows = rows
        oldLines = getattr(self, 'lines', [])
        self.lines = oldLines[:rows]
        self.updateText()
        
    def updateText(self):
        text = u"\n".join(self.lines)
        self.set_text(text)
    

class FileListBox(urwid.ListBox):
    """
    I occupy most of the screen with a list of access log files being
    processed.
    """
    def __init__(self):
        pass

    
