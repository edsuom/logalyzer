#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
LICENSE
Copyright (C) 2015 Tellectual LLC
"""

from twisted.internet import defer

from sasync.database import transact, SA, AccessBroker

import util
from sift import IPMatcher


class DTK(object):
    """
    I maintain an efficient lookup tree for dt-k combinations.
    """
    units = ['year', 'month', 'day', 'hour', 'minute', 'second']

    def __init__(self, rows=[]):
        self.N = 0
        self.x = {}
        self.load(rows)

    def __len__(self):
        return self.N

    def load(self, rows):
        """
        Load a list of dt-k combinations.
        """
        for dtThis, kThis in rows:
            self.set(dtThis, kThis)

    def check(self, dt, k):
        """
        Check the specified dt-k combination, returning C{True} if
        it's in my lookup tree.
        """
        stuff = self.x
        for unitVal in [getattr(dt, x) for x in self.units]:
            if unitVal not in stuff:
                return False
            stuff = stuff[unitVal]
        return (k in stuff)

    def set(self, dt, k):
        """
        Sets an entry in my lookup tree for the specified dt-k
        combination.
        """
        stuff = self.x
        unitList = [getattr(dt, x) for x in self.units]
        for unitName in self.units:
            unitVal = getattr(dt, unitName)
            if unitName == 'second':
                stuff = stuff.setdefault(unitVal, [])
            else:
                stuff = stuff.setdefault(unitVal, {})
        if k not in stuff:
            stuff.append(k)
            self.N += 1


class Transactor(AccessBroker, util.Base):
    """
    I handle transactions for an efficient database of logfile
    entries.

    """
    valueLength = 255
    directValues = ['http', 'was_rd', 'ip']
    indexedValues = ['vhost', 'url', 'ref', 'ua']
    colNames = directValues +\
               ["id_{}".format(x) for x in indexedValues]

    def cacheSetup(self):
        """
        Sets up caches for values written to the indexed value tables
        """
        # We use huge caches because DB access is so slow
        self.cm = util.CacheManager(200)
        self.cachedValues = {}
        for name in self.indexedValues:
            self.cm.new(name)
            self.cachedValues[name] = {}

    def _pendingID(self, name, value, d=None, clear=False):
        if not hasattr(self, '_pendingIDs'):
            self._pendingIDs = {}
        if name not in self._pendingIDs:
            self._pendingIDs[name] = {}
        if clear:
            self._pendingIDs[name].pop(value, None)
        elif d is None:
            return self._pendingIDs[name].get(value, None)
        self._pendingIDs[name][value] = d
    
    @defer.inlineCallbacks
    def startup(self):
        yield self.table(
            'entries',
            SA.Column(
                'dt', SA.DateTime,
                primary_key=True),
            SA.Column(
                'k', SA.SmallInteger,
                primary_key=True,
                autoincrement=False),
            SA.Column('http', SA.SmallInteger, nullable=False),
            SA.Column('was_rd', SA.Boolean, nullable=False),
            SA.Column('ip', SA.String(15), nullable=False),
            
            SA.Column('id_vhost', SA.Integer, nullable=False),
            SA.Column('id_url', SA.Integer, nullable=False),
            SA.Column('id_ref', SA.Integer),
            SA.Column('id_ua', SA.Integer),
        )
        for name in self.indexedValues:
            yield self.table(
                name,
                SA.Column('id', SA.Integer, primary_key=True),
                SA.Column('value', SA.String(self.valueLength)),
            )
        yield self.table(
            'files',
            SA.Column(
                'name', SA.String(self.valueLength), primary_key=True),
            SA.Column('dt', SA.DateTime),
            SA.Column('records', SA.Integer),
        )
        self.pendingID = {}

    @transact
    def preload(self):
        """
        Loads DTK and IPMatcher objects from database (can take a while,
        but do it while waiting for the first result from the log
        reader processes).
        """
        self.dtk = DTK()
        ipm = IPMatcher()
        col = self.entries.c
        for sh in self.selectorator(col.dt, col.k, col.ip):
            pass
        rp = sh()
        rows = rp.fetchmany()
        while rows:
            for row in rows:
                self.dtk.set(row[0], row[1])
                ipm.addIP(row[2], ignoreCache=True)
            rows = rp.fetchmany()
        return ipm

    @transact
    def getEntry(self, dt, k):
        """
        Returns all of the columns after dt, k for one unique dt-k
        combination in the entries table.
        """
        col = self.entries.c
        if not self.s('s_entry'):
            cList = [getattr(col, x) for x in self.colNames]
            self.s(
                cList,
                SA.and_(col.dt == SA.bindparam('dt'),
                        col.k == SA.bindparam('k')))
        return self.s().execute(dt=dt, k=k).first()

    @transact
    def insertEntry(self, dt, k, values):
        """
        Inserts a DB entry for the specified dt-k combination, using the
        supplied dict values.

        You must ensure that the dt-k combination is not already in
        the DB and that there is one value for each name defined in
        I{colNames}.
        """
        print "!IE", dt, k
        print values
        kw = {'dt': dt, 'k': k}
        if len(self.colNames) > len(values):
            
            return
        for kk, name in enumerate(self.colNames):
            kw[name] = values[kk]
        self.entries.insert().execute(**kw)

    
    @defer.inlineCallbacks
    def setEntry(self, dt, k, values):
        """
        Adds a new entry to the database for the specified
        datetime-sequence combination dt-k. See my colNames attribute
        for the six values you need to supply.

        Returns a deferred that fires with one of three status values:

        p: Present: Matching dt-k entry present with identical values,
           nothing added.
        c: Conflict: Matching dt-k entry found, but with differing
           values, you need to add another one with a different k.
        a: Added: No matching dt-k entry found, so one was added.
        """
        def checkExisting(rowValues):
            for kk, value in enumerate(rowValues):
                if value != values[kk]:
                    print "C", dt, k
                    print kk, values[kk], values, rowValues
                    return 'c'
            print "P", dt, k
            print rowValues
            return 'p'

        # Check the lookup tree first
        print "!SE", dt, k
        print values
        pleaseInsert = True
        if self.dtk.check(dt, k):
            # There appears to be a dt-k entry already...
            print "DTK-YES"
            row = yield self.getEntry(dt, k)
            print "GOT ENTRY"
            print row
            if row:
                # ... yes, indeed; check it
                code = yield checkExisting(row)
                pleaseInsert = False
            # ... no, we must have purged it. No biggie.
        if pleaseInsert:
            print "!DTK Inserting"
            # Insert new entry
            yield self.insertEntry(dt, k, values)
            self.dtk.set(dt, k)
            # NOTE: When it hung, it didn't make it to this point!!!
            print "A", dt, k
            print values
            code = 'a'
        defer.returnValue(code)
    
    @transact
    def setNameValue(self, name, value):
        """
        Get the unique ID for this value in the named table, adding a new
        entry for it there if necessary.
        """
        table = getattr(self, name)
        if not self.s("s_{}".format(name)):
            self.s([table.c.id], table.c.value == SA.bindparam('value'))
        row = self.s().execute(value=value).first()
        if row:
            ID = row[0]
            print "SNV-A", name, value, ID
        else:
            rp = table.insert().execute(value=value)
            ID = rp.lastrowid
            print "SNV-B", name, value, ID
        return ID

    @transact
    def getMaxSequence(self, dt):
        if not self.s('max_sequence'):
            c = self.entries.c
            self.s([SA.func.max(c.k)], c.dt == SA.bindparam('dt'))
        return self.s().execute(dt=dt).first()[0]

    def _getID(self, name, value):
        """
        Returns a deferred to the unique ID for the named value in the
        supplied record dict, looked up from the appropriate
        indexed-value table if it's not in my cache for that name.
        
        Runs asynchronously; don't call from a transact method.
        """
        def done(ID):
            # Order of the following two lines could be important
            print "GI", name, value, ID
            valueDict[value] = ID
            self._pendingID(name, value, clear=True)
            return ID

        valueDict = self.cachedValues[name]
        # Truncate any overly long values now, before they cause any
        # complications in the DB check or insertion
        value = value[:self.valueLength]
        # TODO: Restore caching (maybe) when weirdness gets sorted out
        #if self.cm.check(name, value) and value in valueDict:
        if value in valueDict:
            # Cached ID
            print "A", name, value
            return defer.succeed(valueDict[value])
        # Get ID from DB for value, at high priority
        dID = self._pendingID(name, value)
        if dID is None:
            print "B", name, value
            #discardedValue = self.cm.set(name, value)
            #if discardedValue in valueDict:
            #    del valueDict[discardedValue]
            # No pending DB fetches now, so do one in its own 
            # high-priority transaction
            d = self.setNameValue(name, value, niceness=-15)
            self._pendingID(name, value, d)
            d.addCallback(done)
        else:
            print "C", name, value
            d = defer.Deferred()
            d.addCallback(lambda _ : valueDict[value])
            dID.chainDeferred(d)
        d.addErrback(
            self.oops, "Getting ID for '{}' value '{}'", name, value)
        return d

    @defer.inlineCallbacks
    def setRecord(self, dt, k, record):
        """
        Adds all needed database entries for the supplied record at
        the specified datetime-sequence combination dt-k.

        Returns a deferred that fires with C{None} if a new database
        entry was written, a new value of k if there was a conflict
        with an existing dt-k combination and the new value had to be
        obtained, or with the old k value if there was the same exact
        entry (no conflict).

        A conflict exists when there is already an entry for the
        specified dt-k combination that matches values than the ones
        in your supplied record.
        """
        if not hasattr(self, 'cm'):
            self.cacheSetup()
        # Build list of values and indexed-value IDs
        dList = []
        values = [record[x] for x in ('http', 'was_rd', 'ip')]
        for name in self.indexedValues:
            dList.append(self._getID(name, record[name]))
        IDs = yield defer.gatherResults(dList)
        values.extend(IDs)
        # Set the entry in its own transaction (which includes
        # checking for existing ID/value entries)
        print "\n!SR", dt, k
        print record
        print values
        # TODO: Occasionally hangs at this next line!!!
        code = yield self.setEntry(dt, k, values)
        if code == 'p':
            # Entry was already present
            result = k
        if code == 'c':
            # Conflict with existing dt-k combination having different
            # values; need to get a new sequence number for this entry
            maxSequence = yield self.getMaxSequence(dt)
            k = maxSequence + 1
            code = yield self.setEntry(dt, k, values)
            if code == 'c':
                self.msgWarning(
                    "Couldn't add record for {} even with new " +\
                    "sequence number {:d}", dt, k)
            result = k
        elif code == 'a':
            # New entry was added
            result = None
        defer.returnValue(result)

    @transact
    def getValuesFromIDs(self, IDs):
        """
        Call with a list of IDs, one for each of my I{indexedValues}, and
        returns a dict with the name:value items.
        """
        result = {}
        for k, ID in enumerate(IDs):
            name = self.indexedValues[k]
            cols = getattr(getattr(self, name), 'c')
            for sh in self.selectorator(cols.value):
                sh.where(cols.id == ID)
            result[name] = sh().first()[0]
        return result
        
    @defer.inlineCallbacks
    def getRecord(self, dt, k):
        """
        Returns a (deferred) dict containing the record for the specified
        datetime-sequence combination dt-k.
        """
        result = {}
        row = yield self.getEntry(dt, k)
        row = list(row)
        for j, name in enumerate(self.directValues):
            result[name] = row[j]
        valueDict = yield self.getValuesFromIDs(row[3:])
        result.update(valueDict)
        defer.returnValue(result)

    @transact
    def purgeIP(self, ip):
        """
        Purges the database of entries with the specified IP address,
        returning the (deferred) number of rows that were matched and
        presumably deleted.
        """
        rp = self.execute(
            self.entries.delete().where(self.entries.c.ip == ip))
        return rp.rowcount

    @transact
    def hitsForIP(self, ip):
        """
        Returns the number of entries for the specified IP address
        """
        cols = self.entries.c
        for sh in self.selectorator(SA.func.count(cols.http)):
            sh.where(cols.ip == ip)
        return sh().first()[0]

    @transact
    def fileInfo(self, fileName, *args):
        """
        With just fileName, returns the datetime and number of records for
        the file, if one was processed previously and its results
        fully reflected in the DB, or C{None}

        With two additional arguments of a datetime object and an
        integer number of records, updates or inserts an entry for the
        file to indicate that it has been processed and its results
        are fully reflected in the DB.
        """
        cols = self.files.c
        if args:
            # The transact decorator is smart enough to avoid multiple
            # wrapping with a recursive call.
            if self.fileInfo(fileName):
                self.files.update(
                    cols.name == fileName).execute(
                        dt=args[0], records=args[1])
            else:
                self.files.insert().execute(
                    name=fileName, dt=args[0], records=args[1])
            return
        if not self.s("file_info"):
            self.s(
                [cols.dt, cols.records],
                cols.name == SA.bindparam('name'))
        return self.s().execute(name=fileName).first()

    @transact
    def deleteFileInfo(self, fileName):
        """
        Probably don't need this except for testing
        """
        self.files.delete(self.files.c.name == fileName).delete()
    
        
        

                
                
            
