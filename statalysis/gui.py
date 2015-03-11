#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import math

from twisted.internet import reactor

import urwid as u
from urwid.raw_display import Screen


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


class ProgressText(u.Text):
    """
    Call my L{step} method to show progress with a spinning indicator,
    and L{done} to blank out the indicator.
    """
    progressChars = "|/=\\"

    def __init__(self):
        self.k = 0
        self.N = len(self.progressChars)
        super(ProgressText, self).__init__(self.pc())

    def pc(self, k=0):
        return self.progressChars[k]
        
    def step(self):
        self.k = (self.k + 1) % self.N
        self.set_text(self.pc(self.k))

    def done(self):
        self.set_text(self.pc())


class FileRow(u.ListBox):
    """
    I am one row of your status-updatable file list.
    """
    gutterWidth = 2

    def __init__(self, fileName, leftColWidth, totalWidth):
        self.p = ProgressText()
        self.leftColWidth = leftColWidth
        self.statusText = ""
        self.status = u.Text("", wrap='clip')
        self.rowWidgets = u.Columns([
            # File name
            (leftColWidth, u.Text(fileName, align='right')),
            # Progress indicator
            (1, self.p),
            # Status line
            (self._rightColWidth(totalWidth), self.status),
        ], dividechars=self.gutterWidth)
        rowList = u.SimpleListWalker([self.rowWidgets])
        super(FileRow, self).__init__(rowList)

    def _rightColWidth(self, totalWidth):
        return totalWidth - self.leftColWidth - 1 - 2*self.gutterWidth
        
    def updateWidth(self, width):
        self.status = u.Text(self.statusText, wrap='clip')
        widget, options = self.rowWidgets.contents[2]
        self.rowWidgets.contents[2] = (
            self.status,
            self.rowWidgets.options(
                'given', self._rightColWidth(width)))
    
    def step(self):
        self.p.step()

    def done(self):
        self.p.done()

    def setStatus(self, text):
        self.statusText = text
        self.status.set_text(text)
    
        
class Files(u.GridFlow):
    """
    I occupy most of the screen with a list of access log files being
    processed.
    """
    gutterWidth = 2
    minRightColWidth = 40
    
    def __init__(self, fileNames, width):
        self.fileNames = fileNames
        self.leftColWidth = max([len(x) for x in fileNames])
        cellWidth = self._cellWidth(width)[0]
        widgetList = [
            u.BoxAdapter(FileRow(x, self.leftColWidth, cellWidth), 1)
            for x in fileNames]
        super(Files, self).__init__(
            widgetList, cellWidth, self.gutterWidth, 0, 'left')

    def _cellWidth(self, totalWidth):
        def floorRatio(x, y):
            return int(math.floor(float(x)/y))
        
        minCellWidth = self.leftColWidth + 1 +\
                       2*FileRow.gutterWidth + self.minRightColWidth
        nCols = floorRatio(totalWidth, minCellWidth)
        return floorRatio(totalWidth, nCols), nCols
        
    def _row(self, fileName):
        return self.contents[self.fileNames.index(fileName)][0]

    def updateWidth(self, width):
        cellWidth = self._cellWidth(width)[0]
        for k, stuff in enumerate(self.contents):
            widget, options = stuff
            widget.updateWidth(width)
            self.contents[k] = (widget, self.options(width_amount=cellWidth))
    
    def indicator(self, fileName):
        """
        Gives the progress indicator a spin to show progress being made on
        the specified file.
        """
        self._row(fileName).step()
    
    def setStatus(self, fileName, textProto, *args):
        """
        Updates the status for the specified file with the supplied text,
        clearing the progress indicator.
        """
        if fileName not in self.fileNames:
            raise IndexError("Unknown filename '{}'".format(fileName))
        row = self._row(fileName)
        row.done()
        row.setStatus(textProto.format(*args))

    
class GUI(object):
    """
    I am the main curses interface.
    """
    title = "Statalysis"
    
    palette = [
        # Name
        # 'fg color,setting', 'background color', 'mono setting'
        ('heading',
         'dark cyan', 'default', 'bold'),
        ('heading_current',
         'yellow,bold', 'default', 'bold'),
    ]
    
    def __init__(self):
        self.id_counter = 0
        # A screen is useful right away
        self.screen = Screen()
        self.screen.register_palette(self.palette)
        self.screen.set_terminal_properties(
            colors=16,
            bright_is_bold=True)

    def start(self, fileNames):
        # The top-level widgets
        self.m = Messages()
        self.f = Files(fileNames, self._dims()[0])
        p = u.Pile([u.Divider("=", 1, 1), self.f, u.Divider(" ")])
        main = u.WidgetWrap(
            u.LineBox(
                u.Padding(
                    u.Frame(self.m, footer=p),
                    left=1, right=1),
                title=self.title))
        eventLoop = u.TwistedEventLoop(reactor, manage_reactor=False)
        self.formerDims = self._dims()
        self.loop = u.MainLoop(
            main, screen=self.screen,
            unhandled_input=self.possiblyQuit, event_loop=eventLoop)
        reactor.addSystemEventTrigger('before', 'shutdown', self.stop)
        self.loop.start()

    def _dims(self):
        # Deduct 4 from each dimension due to outline and padding
        return [x-4 for x in self.screen.get_cols_rows()]

    def update(self):
        width, height = self._dims()
        # Update for new width
        if width != self.formerDims[0]:
            self.f.updateWidth(width)
        self.loop.draw_screen()

    def stop(self):
        self.screen.unhook_event_loop(self.loop)
        self.loop.stop()

    def possiblyQuit(self, key):
        if key in ('q', 'Q'):
            reactor.stop()
    
    def msgHeading(self, textProto, *args):
        self.id_counter += 1
        ID = self.id_counter
        self.m.heading(textProto.format(*args), ID)
        self.update()
        return ID

    def msgBody(self, ID, textProto, *args):
        self.m.msg(textProto.format(*args), ID)
        self.update()

    def fileStatus(self, fileName, *args):
        if args:
            self.f.setStatus(fileName, *args)
        else:
            self.f.indicator(fileName)
        self.update()


        
