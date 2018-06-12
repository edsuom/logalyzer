#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# logalyzer:
# Parses your bloated HTTP access logs to extract the info you want
# about hits from (hopefully) real people instead of just the endless
# stream of hackers and bots that passes for web traffic
# nowadays. Stores the info in a relational database where you can
# access it using all the power of SQL.
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

"""
Command-line sort-of GUI using ncurses.
"""

import sys, math

from twisted.internet import reactor, defer
import twisted.python.log

from asynqueue.info import Info

import urwid as u
from urwid.raw_display import Screen

class MessageBox(u.ListBox):
    """
    I am a message box consisting of a heading and an expandable space
    for lines you can add under the heading.
    """
    def __init__(self, text):
        self.hText = text
        self.height = 1
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
        self.body.append(u.Text(('message', text)))
        self.setCurrent(True)
        self.height += 1

    def progress(self, N):
        """
        Call this to establish a progress counter and increment it by I{N}
        with each new call.
        """
        def pcText():
            return ('message', "-- {:d} --".format(self.pc))
        
        if hasattr(self, 'pc'):
            self.pc += N
            self.pcWidget.set_text(pcText())
        else:
            self.pc = N
            self.pcWidget = u.Text(pcText())
            self.body.append(self.pcWidget)
            self.height += 1


class Messages(u.ListBox):
    """
    I provide a place for status messages to be displayed below headings.

    A heading will be set off from anything above it, and provides an
    anchor for messages. Each message will be appended below the
    heading with its ID.

    """
    defaultHeight = 3
    orphanHeading = ""
    
    def __init__(self):
        self.boxes = []
        body = u.SimpleFocusListWalker([])
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

    def _boxerator(self, ID):
        if ID not in self.boxes:
            raise IndexError(
                "No heading for ID '{}'".format(ID))
        k = self.boxes.index(ID)
        # De-emphasize any other boxes
        for kk, msgBox in enumerate(self.body):
            if kk != k:
                msgBox.setCurrent(False)
        # Get and yield the MessageBox instance
        msgBox = self.body[k]
        # -----------------------
        yield msgBox
        # -----------------------
        # Add the message line under the heading
        newHeight = msgBox.height
        if newHeight > self.defaultHeight:
            rawBox = self.body[k].original_widget
            self.body[k] = self.adapt(rawBox, newHeight)
        # Set focus to this last-added message
        self.body.set_focus(k)
        
    def msg(self, text, ID=None):
        if ID is None and ID not in self.boxes:
            # Need a (blank) heading for orphan messages
            self.boxes.append(None)
            msgBox = self.adapt(MessageBox(self.orphanHeading))
            self.body.append(msgBox)
        # Orphan or not, there should be a heading now
        for msgBox in self._boxerator(ID):
            msgBox.add(text)

    def distinctMsg(self, label, text):
        labelText = label.upper()
        self.boxes.append(labelText)
        height = 2
        msgText = [
            "\n", ('{}_label'.format(label), "{}:".format(labelText))]
        for line in text.split('\n'):
            height += 1
            msgText.append((label, "\n" + line.rstrip()))
        msgBox = self.adapt(MessageBox(msgText), height=height)
        self.body.append(msgBox)

    def progress(self, ID, N):
        for msgBox in self._boxerator(ID):
            msgBox.progress(N)


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

    def pc(self, k=None):
        if k is None:
            return "+"
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
    minRightColWidth = 25

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
    
    def __init__(self, fileNames, width):
        self.fileNames = fileNames
        self.leftColWidth = max([len(x) for x in fileNames])
        cellWidth, nCols = self._cellWidth(width)
        widgetList = [
            u.BoxAdapter(FileRow(x, self.leftColWidth, cellWidth), 1)
            for x in fileNames]
        super(Files, self).__init__(
            widgetList, cellWidth, self.gutterWidth, 0, 'left')

    def _cellWidth(self, totalWidth):
        def floorRatio(x, y):
            ratio = float(x) / y
            return int(math.floor(ratio))
        
        minCellWidth = \
            self.leftColWidth + 1 +\
            2*FileRow.gutterWidth + FileRow.minRightColWidth
        nCols = floorRatio(totalWidth, minCellWidth)
        if nCols:
            totalWidth -= self.gutterWidth*(nCols-1)
            return floorRatio(totalWidth, nCols), nCols
        # Not sure why nCols would ever come out zero, but this is a
        # fail-safe
        return totalWidth, 1
        
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


class StdSubstitute(object):
    """
    Substitute sink for stdout and stderr when the GUI is used, to
    avoid garbage characters messing up the terminal. Also acts as a
    Twisted log observer.
    """
    def __init__(self, name, gui):
        self.name = name
        self.gui = gui
    
    def write(self, text):
        self.gui.warning("{}: {}", self.name, text)
    def writelines(self, lines):
        self.write("\n".join(lines))
    def flush(self):
        self.gui.update()
    def close(self):
        pass
    def __call__(self, logEvent):
        text = "\n".join(logEvent['message'])
        if logEvent['isError']:
            if 'failure' in logEvent:
                text += "\n{}".format(
                    Info().aboutFailure(logEvent['failure']))
            self.gui.error("Twisted Error: {}", text)
        else:
            self.gui.warning("Twisted Message: {}", text)

            
class GUI(object):
    """
    I am the main curses interface.
    """
    title = "Logalyzer"
    
    palette = [
        # Name
        # 'fg color,setting', 'background color', 'mono setting'
        ('heading',
         'dark cyan', 'default', 'default'),
        ('heading_current',
         'light cyan,underline', 'default', 'underline'),
        ('message',
         'white', 'default', 'default'),
        ('error_label',
         'light red,underline', 'default', 'underline'),
        ('error',
         'brown', 'default', 'default'),
        ('warning_label',
         'yellow,underline', 'default', 'underline'),
        ('warning',
         'brown', 'default', 'default'),
    ]
    
    def __init__(self, stopperFunction):
        self.running = False
        self.stopperFunction = stopperFunction
        self.id_counter = 0
        # A screen is useful right away
        self.screen = Screen()
        self.screen.register_palette(self.palette)
        self.screen.set_mouse_tracking(True)

    def start(self, fileNames):
        """
        Constructs my widgets and starts my event loop and main loop.
        """
        def possiblyQuit(key):
            if key in ('q', 'Q'):
                if not hasattr(self, '_stopping'):
                    self._stopping = None
                    self.warning("Shutting down, please wait...")
                    if reactor.running:
                        # I trust the stopper function to call my stop
                        # method at the appropriate time
                        reactor.callFromThread(reactor.stop)
                
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
            unhandled_input=possiblyQuit, event_loop=eventLoop)
        reactor.addSystemEventTrigger('after', 'shutdown', self.stop)
        #sys.stdout = StdSubstitute('STDOUT', self)
        sys.stderr = observer = StdSubstitute('STDERR', self)
        twisted.python.log.addObserver(observer)
        self.running = True
        self.loop.start()
    
    def _dims(self):
        # Deduct 4 from each dimension due to outline and padding
        return [x-4 for x in self.screen.get_cols_rows()]

    def update(self):
        """
        Updates my display, possibly with an updated screen width.
        """
        if not self.running:
            return
        width, height = self._dims()
        # Update for new width
        if width != self.formerDims[0]:
            self.f.updateWidth(width)
        self.loop.draw_screen()

    def stop(self):
        """
        Tears down the GUI display. This will be called by
        L{main.Recorder.shutdown} after all other shutdown steps are
        done, as part of the Twisted reactor shutdown.
        """
        if self.running and not hasattr(self, '_shutdownFlag'):
            self._shutdownFlag = None
            self.running = False
            self.screen.unhook_event_loop(self.loop)
            self.loop.stop()
    
    def msgHeading(self, textProto, *args):
        """
        Sends a new heading to my scrolling message window. You can supply
        a single string, or a string prototype followed by one or more
        formatting arguments.

        Returns a unique integer ID for this heading. Use that when
        supplying lines of message body under this heading.
        """
        self.id_counter += 1
        ID = self.id_counter
        self.m.heading(textProto.format(*args), ID)
        self.update()
        return ID

    def msgBody(self, ID, textProto, *args):
        """
        Adds a new line of message body under heading ID. You can supply a
        single string after the integer ID, or a string prototype
        followed by one or more formatting arguments.
        """
        text = textProto.format(*args)
        self.m.msg(text, ID)
        self.update()

    def msgOrphan(self, textProto, *args):
        """
        Adds a new line of message body under a (possibly blank) orphan
        heading ID. You can supply a single string, or a string
        prototype followed by one or more formatting arguments.
        """
        text = textProto.format(*args)
        self.m.msg(text)
        self.update()

    def warning(self, textProto, *args):
        """
        Adds a distinctive warning message to the message window.
        """
        self.m.distinctMsg('warning', textProto.format(*args))
        self.update()
        
    def error(self, textProto, *args):
        """
        Adds a distinctive error message to the message window.
        """
        self.m.distinctMsg('error', textProto.format(*args))
        self.update()

    def msgProgress(self, ID, N):
        self.m.progress(ID, N)
        self.update()
        
    def fileStatus(self, fileName, *args):
        """
        Updates the status entry for the specified fileName. With no
        further arguments, the progress indicator for the file is
        given a spin. With a string or string prototype followed by
        formatting arguments, the progress indicator is reset and the
        brief status text following the filename is updated.
        """
        if args:
            self.f.setStatus(fileName, *args)
        else:
            self.f.indicator(fileName)
        self.update()


        
