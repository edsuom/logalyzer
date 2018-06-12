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

"""
SQL database access using sAsync.
"""

from zope.interface import implements
from twisted.internet import defer
from twisted.internet.interfaces import IConsumer

from asynqueue.info import showResult, whichThread
from asynqueue.iteration import ListConsumer

from sasync.database import transact, wait, SA, AccessBroker

import util
from sift import IPMatcher


class DTK(object):
    """
    I maintain a CPU-efficient but somewhat memory expensive lookup
    tree for datetime objects.
    """
    units = ['year', 'month', 'day', 'hour', 'minute', 'second']

    def __init__(self, rows=[]):
        self.N = 0
        self.x = {}
        self.load(rows)
        self._pending = True

    def __len__(self):
        return self.N

    def isPending(self, *args):
        if args:
            self._pending = args[0]
        return self._pending
        
    def load(self, rows):
        """
        Load a list of datetime objects or rows whose first element is
        a datetime object.
        """
        for dt in rows:
            if isinstance(dt, (list, tuple)):
                dt = dt[0]
            self.set(dt)

    def _uniterator(self, dt):
        """
        Iterates over values for each time unit of the supplied
        datetime object, yielding an integer number of positions to
        the last time unit and the value for that time unit.
        """
        N = len(self.units)
        for k, unitName in enumerate(self.units):
            yield N-k-1, getattr(dt, unitName)

    def check(self, dt):
        """
        Check the specified datetime object, returning C{True} if it's
        in my lookup tree.
        """
        stuff = self.x
        for p, unitVal in self._uniterator(dt):
            if unitVal not in stuff:
                return False
            if p > 0:
                stuff = stuff[unitVal]
        return True

    def set(self, dt):
        """
        Sets an entry in my lookup tree for the specified datetime
        object.
        """
        stuff = self.x
        for p, unitVal in self._uniterator(dt):
            if p > 1:
                stuff = stuff.setdefault(unitVal, {})
            elif p == 1:
                stuff = stuff.setdefault(unitVal, [])
            elif unitVal not in stuff:
                stuff.append(unitVal)
                self.N += 1


class PreloadConsumer(object):
    """
    I consume single-item query results, doing the specified f-args-kw
    for each.

    @ivar N: The number of rows between calls to I{progressCall}.
    """
    implements(IConsumer)

    def __init__(self, f, **kw):
        self.f = f
        self.kw = kw
        self.count = 0
        self.N = kw.pop('N', 100)
        self.progressCall = kw.pop('progressCall', None)
    
    def registerProducer(self, producer, streaming):
        pass
    def unregisterProducer(self):
        pass
        
    def write(self, rows):
        """
        All I care about is having rows written. If you specified a
        I{progressCall} to my constructor, I will call it with no
        argument every I{N} rows.
        """
        for row in rows:
            if isinstance(row, SA.engine.RowProxy):
                row = row[0]
            self.f(row, **self.kw)
            self.count += 1
            if not self.count % self.N and callable(self.progressCall):
                self.progressCall()


class RecordConsumer(ListConsumer):
    """
    I consume rows and make them into records.
    """
    @defer.inlineCallbacks
    def processItem(self, row):
        ID = row[0]
        result = {}
        for j, name in enumerate(self.t.directValues):
            result[name] = row[j+1]
        valueDict = yield self.t._getValuesFromIDs(row[4:])
        result.update(valueDict)
        defer.returnValue((ID, result))


class Transactor(AccessBroker, util.Base):
    """
    I handle transactions for an efficient database of logfile
    entries.

    @ivar ipm: An instance of L{sift.IPMatcher} containing all IP
      addresses in the database.

    @ivar dtk: An instance of L{DTK} loaded (eventually) with all
      datetime values in the database.
    
    """
    directValues = ['ip', 'http', 'was_rd']
    indexedValues = ['vhost', 'url', 'ref', 'ua']
    colNames = directValues +\
               ["id_{}".format(x) for x in indexedValues]

    @defer.inlineCallbacks
    def startup(self):
        # Primary key is an auto-incrementing index, which can be used
        # to find out the order in which requests were made within a
        # single second.
        yield self.table(
            'entries',
            SA.Column('id', SA.Integer, primary_key=True),
            SA.Column('dt', SA.DateTime),
            SA.Column('ip', SA.String(15)),
            SA.Column('http', SA.SmallInteger),
            SA.Column('was_rd', SA.Boolean),
            SA.Column('id_vhost', SA.Integer),
            SA.Column('id_url', SA.Integer),
            SA.Column('id_ref', SA.Integer),
            SA.Column('id_ua', SA.Integer),
            index_dt=['dt'], index_ip=['ip']
        )
        kw = {}
        if str(self.q.engine.url).startswith('mysql'):
            kw['collation'] = "latin1_general_cs"
        for name in self.indexedValues:
            yield self.table(
                name,
                SA.Column('id', SA.Integer, primary_key=True),
                SA.Column('value', SA.String(255, **kw)),
                unique_value=['value']
            )
        yield self.table(
            'files',
            SA.Column(
                'name', SA.String(255), primary_key=True),
            SA.Column('dt', SA.DateTime),
            SA.Column('bytes', SA.Integer),
            SA.Column('records', SA.Integer),
        )
        self.pendingID = {}
        self.dtk = DTK()
        self.ipm = IPMatcher()
        self.idTable = {}
        for name in self.indexedValues:
            self.idTable[name] = {}

            
    # Public API
    # -------------------------------------------------------------------------
        
    def preload(self, progressCall=None, N_batch=10, N_progress=100):
        """
        Loads my DTK object from the database. Returns a C{Deferred} that
        fires with the number of IPs in the database.

        You can use the DTK object via L{dtk} in the meantime; doing
        so will save you more and more time as the entries load from
        the database.
        """
        def load(colName, f, **kw):
            consumer = PreloadConsumer(f, **kw)
            s = self.select([getattr(col, colName)], distinct=True)
            return self.selectorator(s, consumer, N=N_batch)

        @defer.inlineCallbacks
        def run():
            # DTK, which we don't need to wait for
            load('dt', self.dtk.set).addCallback(
                lambda _: self.dtk.isPending(False))
            # IP matcher, which we do
            yield load(
                'ip', self.ipm.addIP,
                progressCall=progressCall, N=N_progress)
            defer.returnValue(len(self.ipm))

        col = self.entries.c
        return self.callWhenRunning(run)

    @wait
    @defer.inlineCallbacks
    def setRecord(self, dt, record):
        """
        Adds all needed database entries for the supplied record at the
        specified datetime.

        @return: A C{Deferred} that fires with a bool indicating if a
          new entry was added.
        
        """
        self.ipm.addIP(record['ip'])
        # Build list of values and indexed-value IDs
        values = [record[x] for x in self.directValues]
        for name in self.indexedValues:
            value = record[name][:255]
            if value in self.idTable[name]:
                # We've set this value already
                ID = self.idTable[name][value]
            else:
                ID = yield self.setNameValue(name, value, niceness=-15)
                # Add to idTable for future reference, avoiding DB checks
                self.idTable[name][value] = ID
            values.append(ID)
        # With this next line commented out and result = False
        # instead, the memory leak still persists. CPU time for the
        # main process was 66% of normal.
        result = yield self.setEntry(dt, values)
        defer.returnValue(result)

    @wait
    def getRecords(self, dt):
        """
        Returns a (deferred) list of all the records for the specified
        datetime, in the order they were originally written.

        Note: This method requires DB connection pooling.
        """
        def done(null):
            return lc().addCallback(gotList)
        def gotList(recordList):
            return [xy[1] for xy in sorted(recordList, key=lambda xy: xy[0])]
        if self.singleton:
            raise util.DatabaseError(
                "Database must support connection pooling")
        lc = RecordConsumer(t=self)
        # I got into trouble ignoring the deferred returned from the
        # transaction that fires when all iterations are done. Calling
        # this after setRecord doesn't work unless I wait for the
        # iterations-done deferred and ALSO (then?) call the
        # ListConsumer. Weird.
        return self.getEntries(dt, consumer=lc).addCallback(done)
        
    @transact
    def purgeIP(self, ip, ignoreIPM=False):
        """
        Purges the database of entries with the specified IP address,
        returning the (deferred) number of rows that were matched and
        presumably deleted.
        """
        # The purge
        if ignoreIPM or self.ipm(ip):
            # The in-database IP matcher says it's in the database so it
            # needs to be removed...
            self.ipm.removeIP(ip)
            with self.selex(self.entries.delete) as sh:
                sh.where(self.entries.c.ip == ip)
                result = sh().rowcount
        else:
            # No purge needed
            result = 0
        return result

    @transact
    def hitsForIP(self, ip):
        """
        Returns the number of entries for the specified IP address
        """
        cols = self.entries.c
        with self.selex(SA.func.count(cols.http)) as sh:
            sh.where(cols.ip == ip)
            result = sh().scalar()
        return result

    @transact
    def fileInfo(self, fileName, *args):
        """
        With just I{fileName} as an argument, returns the datetime and
        number of records for the file, if one was processed
        previously and its results are fully reflected in the DB, or
        C{None}

        With three additional arguments of a datetime object, an
        integer file size (in bytes), and an integer number of
        records, the method updates or inserts an entry for the file
        to indicate that it has been processed and its results are
        fully reflected in the DB.
        """
        cols = self.files.c
        if args:
            # The transact decorator is smart enough to avoid multiple
            # wrapping with a recursive call.
            if self.fileInfo(fileName):
                self.files.update(
                    cols.name == fileName).execute(
                        dt=args[0], bytes=args[1], records=args[2])
            else:
                self.files.insert().execute(
                    name=fileName, dt=args[0], bytes=args[1], records=args[2])
            return
        if not self.s("file_info"):
            self.s(
                [cols.dt, cols.bytes, cols.records],
                cols.name == SA.bindparam('name'))
        return self.s().execute(name=fileName).first()

    # More or less internal methods
    # -------------------------------------------------------------------------

    @transact
    def insertEntry(self, dt, values):
        """
        Inserts a DB entry for the specified datetime, using the supplied
        dict of values, which are index integers for indexed values.

        You must ensure that there is one value for each name
        defined in I{colNames}.

        Returns a unique integer ID for the new entry.
        """
        kw = {'dt': dt}
        N = [len(x) for x in (self.colNames, values)]
        if N[0] > N[1]:
            self.msgWarning("Need {:d} values entries, only got {:d}", *N)
            return
        for k, name in enumerate(self.colNames):
            kw[name] = values[k]
        rp = self.entries.insert().execute(**kw)
        ID = rp.lastrowid
        # Necessary?
        rp.close()
        return ID

    @defer.inlineCallbacks
    def setEntry(self, dt, values):
        """
        Adds a new entry to the database for the specified datetime
        dt. See my colNames attribute for the six values you need to
        supply.

        Returns a deferred that fires with a Bool indicating if a new
        entry was added
        """
        ID = None
        # Check the lookup tree first
        if self.dtk.isPending() or self.dtk.check(dt):
            ip = values[0]
            # There is at least one entry for this dt...
            if self.ipm(ip):
                # ...and an entry somewhere with this IP address, so
                # check for an existing entry for this dt with
                # identical values
                ID = yield self.matchingEntry(dt, values)
        # Will we be inserting a new entry?
        if ID is None:
            # Yes, do it now
            self.dtk.set(dt)
            wasInserted = True
            yield self.insertEntry(dt, values)
        else:
            wasInserted = False
        defer.returnValue(wasInserted)

    @defer.inlineCallbacks
    def matchingEntry(self, dt, values):
        """
        Returns a deferred that fires with the integer ID of the DB entry
        for the specified datetime and list of values (in the order of
        the I{colNames} list, some values being integer indices), or
        C{None} if there is no such entry.
        """
        def matchingValues():
            ID = theseValues[0]
            for k, value in enumerate(theseValues[1:]):
                if value != values[k]:
                    return
            return ID

        ID = None
        entries = yield self.getEntries(dt, asList=True)
        for theseValues in entries:
            ID = matchingValues()
            if ID is not None:
                break
            # Yep, one was found, no new entry will be needed
        defer.returnValue(ID)

    @transact
    def getEntries(self, dt):
        """
        Returns the ID plus all of the columns after dt for one datetime
        second of entries.
        """
        col = self.entries.c
        if not self.s('s_entry'):
            cList = [self.entries.c.id]
            cList += [getattr(col, x) for x in self.colNames]
            self.s(cList, col.dt == SA.bindparam('dt'))
        return self.s().execute(dt=dt)

    @transact
    def setNameValue(self, name, value):
        """
        Get the unique ID for this value in the named table, adding a new
        entry for it there if necessary.
        """
        table = getattr(self, name)
        if not self.s("s_{}".format(name)):
            self.s([table.c.id], table.c.value == SA.bindparam('value'))
        ID = self.s().execute(value=value).scalar()
        if ID is None:
            rp = table.insert().execute(value=value)
            ID = rp.lastrowid
            rp.close()
        return ID
       
    @transact
    def _getValuesFromIDs(self, IDs):
        """
        Call with a list of IDs, one for each of my I{indexedValues}, and
        returns a dict with the name:value items.
        """
        result = {}
        for k, ID in enumerate(IDs):
            name = self.indexedValues[k]
            cols = getattr(getattr(self, name), 'c')
            with self.selex(cols.value) as sh:
                sh.where(cols.id == ID)
                rp = sh()
                result[name] = rp.scalar()
        return result


        
        

                
                
            
