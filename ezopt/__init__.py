"""
EZOPT: Easy option parsing for python scripts
Copyright (C) 2004-5 Edwin A. Suominen

This code is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License ('GPL') as published by the Free
Software Foundation; either version 2 of the License, or at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GPL for more details.

You probably have several hundred more or less identical copies of the GPL on
your system. Just type 'locate COPYING' in your shell to see a list.

"""

# Stdlib imports
import getopt, sys, re, os, textwrap, types
import parser, symbol, token
from shutil import copyfile
from optparse import OptionParser
from commands import mkarg

# PyPI imports
import pyparsing as pp


class Docstring(object):
    """
    I provide a file docstring parser. Call an instance of me to get a file's
    docstring. If the file specified is a compiled .pyc or .pyo, I'll look for
    the original .py file instead.
    """
    dsLines = None
    reExtension = re.compile("^(.+\.py)[co]$")
    reOpenQuote = re.compile("^(\"{3}|\"|\')(.*)$")
    reCloseQuote = re.compile("^(.*?)(\"{3}|\"|\')$")

    def addLine(self, line):
        if self.dsLines is None:
            self.dsLines = []
        #print "%d: '%s'" % (len(self.dsLines)+1, line.strip())
        self.dsLines.append(line.strip())
    
    def __call__(self, filePath):
        """
        Returns the doc string of file
        """
        M = self.reExtension.match(filePath)
        if M is not None:
            filePath = M.group(1)
        fh = open(filePath)
        for line in fh:
            if self.dsLines:
                M = self.reCloseQuote.match(line)
                if M is None:
                    self.addLine(line)
                else:
                    self.addLine(M.group(1))
                    break
            else:
                M = self.reOpenQuote.match(line)
                if M is not None:
                    leadText = M.group(2)
                    if not leadText.endswith("\\"):
                        self.addLine(leadText)
        fh.close()
        return "\n".join(self.dsLines).strip()


class Opt(object):
    """
    I look for the first file listed in sys.argv (or a specified file)
    that has a docstring, and parse the docstring to provide
    positional arguments and keyword options. I act like a list to
    provide positional arguments with sequence methods (me[0],
    me[1:2], etc.) and act like a dict to provide options with mapping
    methods (me['s'], me.items(), etc.)

    I serve as an iterable to return positional arguments, not options. Anyone
    wanting to iterate on options can use my .items() method.
    """
    sections = {}
    options = {}
    args = []
    
    def __init__(self, source=None, noParse=False):
        # Set some private attributes
        doc = Docstring()
        for srcFile in [source] + sys.argv:
            if srcFile is None:
                continue
            if not os.path.isfile(srcFile):
                continue
            docstring = doc(srcFile)
            if docstring is not None:
                try:
                    self._setup(docstring)
                    break
                except:
                    pass
        self.srcFile = srcFile
        # Option parser setup
        usage = []
        for textBlock in self.usageGen():
            usage.append(textBlock)
        self.opt = OptionParser(usage='\n\n'.join(usage))
        self.opt.add_option(
            "--source",
            action="callback",
            callback=self.printSource,
            help="show source code and exit")
        if self.sections.has_key('license'):
            self.opt.add_option(
                "--license",
                action="callback",
                callback=self.printLicense,
                help="show license and exit")
        if self.sections.has_key('options'):
            self._optParser(self.sections['options'])
        # Do an initial setup based on current sys.argv, unless noParse is
        # True, e.g., for testing. Client can rerun my public parse() method,
        # e.g., for testing
        if not noParse:
            self.parse()
    
    def _setup(self, docstring):
        """
        Builds a dict of docstring sections
        """
        self.wrapper = textwrap.TextWrapper(
            initial_indent='  ', subsequent_indent='  ')
        for name, value in self.sectionGen(docstring, '[A-Z]+$'):
            self.sections[name] = value.strip('\n')
        # Save the docstring for my methods to use
        self.docstring = docstring

    def __getattr__(self, name):
        if hasattr(self.options, name):
            return getattr(self.options, name)
        if hasattr(self.args, name):
            return getattr(self.args, name)
        raise AttributeError, "No attribute '%s'" % (name,)

    def __iter__(self):
        self.k = 0
        return self

    def next(self):
        self.k += 1
        if self.k > len(self):
            raise StopIteration()
        return self[self.k-1]
    
    def __getitem__(self, item):
        """
        Returns the value of an option (when name is a string) or a positional
        argument (when name is an integer)
        """
        if type(item) in types.StringTypes:
            # Item specified with a string, return an option like I'm a dict
            return getattr(self.options, item)
        elif type(item) is types.IntType:
            # Item specified with an int, return an arg like I'm a tuple
            if item+1 > len(self.args):
                raise AttributeError(
                    "Can't get argument #%u from a %u-argument list" \
                    % (item, len(self.args)))
            return self.args[item]
        else:
            raise AttributeError(
                "Ask for option items with strings, arg items with integers")

    def __getslice__(self, k1, k2):
        return [self.__getitem__(item) for item in range(k1,k2)]

    def __len__(self):
        return len(self.args)

    def sectionGen(self, text, regex):
        """
        Generator that yields sections of a text block delimited by regex
        """
        section = None
        sectionLines = []
        regex = re.compile(regex)
        # Loop over all lines of docstring
        for line in text.splitlines():
            m = regex.match(line)
            if m is not None:
                # New/first section heading encountered
                if sectionLines:
                    yield (section, '\n'.join(sectionLines))
                section = m.group().lower()
                sectionLines = []
            elif section is not None:
                # Line belonging to a section
                sectionLines.append(line)
        if sectionLines:
            # Yield the final section
            yield (section, '\n'.join(sectionLines))

    def parse(self):
        """
        Sets me up for returning virtual attributes
        """
        self.options, self.args = self.opt.parse_args()
        self.argc = len(self.args)

    def usageGen(self):
        """
        Uses various sections of the docstring to setup my args parser
        for argument and usage
        """
        # SYNOPSIS
        if self.sections.has_key('synopsis'):
            synopsis = self.sections['synopsis']
        else:
            synopsis = "\%prog [options] [args ...]"
        yield synopsis
        # NAME
        if self.sections.has_key('name'):
            yield self.sections['name'].strip() + ':'
        # DESCRIPTION
        if self.sections.has_key('description'):
            # Insert newlines at the beginning and end to ensure we have an
            # initial section heading
            text = '\n' + self.sections['description']
            for null, para in self.sectionGen(text, '^\s*$'):
                yield self.wrapper.fill(para)

    def _optParser(self, text):
        """
        Parses an OPTIONS section of a docstring to setup my args parser for
        options
        """
        option = pp.Word('-', min=1, max=2) + pp.Word(pp.alphas)
        # No-value option parser
        nParser = option + \
                  pp.Optional(pp.Literal(',').suppress() + option) + \
                  pp.LineStart() + pp.restOfLine
        # Value option parser
        vParser = option + \
                  pp.Optional(pp.Literal(',').suppress() + option) + \
                  pp.Word(pp.alphas) + \
                  pp.LineStart() + pp.restOfLine
        for parser in (nParser, vParser):
            # For each option entry found, add the option to the args parser
            for tokens, start, end in parser.scanString(text):
                tokens = list(tokens)
                # First option listed (long or short) is attribute name
                attrName = tokens[1]
                methodArgs = []
                # Arguments to add_option method are strings of options
                # assembled from all dash,name pairs present
                while len(tokens) > 1+(parser==vParser):
                    optString = tokens.pop(0) + tokens.pop(0)
                    methodArgs.append(optString)
                # Add the option, with metavar if value parser
                helpText = tokens[-1][0].lower() + tokens[-1][1:]
                kw = {'dest':attrName, 'help':helpText}
                if parser == vParser:
                    # Symbolic value of option is printed in usage with
                    # 'metavar'
                    kw['metavar'] = tokens[0].strip("<>")
                    kw['type'] = 'string'
                else:
                    # No-value option, set to true if set, false otherwise
                    kw['action'] = 'store_true'
                    kw['default'] = False
                self.opt.add_option(*methodArgs, **kw)
    
    def printSource(self, *args, **kw):
        """
        Sends the source of the client script to stdout. Strips out the
        (probably long) module docstring
        """
        newDocString = "(Omitted script's %i-line docstring for clarity)" % \
                       (self.docstring.count('\n')+1)
        fh = open(self.srcFile, 'r')
        text = fh.read().replace(self.docstring, newDocString, 1)
        fh.close()
        # Use vim as a colorizing pager if available
        cmd = "view -c %s -" % mkarg("set ft=python")
        try:
            fh = os.popen(cmd, 'w')
            fh.write(text)
            fh.close()
        except:
            print text
        sys.exit(0)

    def printLicense(self, *args, **kw):
        """
        Sends the license section of the client script's doc string to stdout.
        """
        text = '\n' + self.sections['license']
        for null, para in self.sectionGen(text, '^$'):
            print textwrap.fill(para), '\n'
        sys.exit(0)
