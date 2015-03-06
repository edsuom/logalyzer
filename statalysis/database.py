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


class Transactor(AccessBroker, util.Base):
    """
    I handle transactions for an efficient database of logfile
    entries.
    """
    directValues = ['http', 'was_rd', 'ip']
    indexedValues = ['vhost', 'url', 'ref', 'ua']
    colNames = directValues +\
               ["id_{}".format(x) for x in indexedValues]

    def cacheSetup(self):
        """
        Sets up caches for values written to the indexed value tables
        """
        self.cm = util.CacheManager()
        self.cachedValues = {}
        for name in self.indexedValues:
            self.cm.new(name)
            self.cachedValues[name] = {}
    
    @defer.inlineCallbacks
    def startup(self):
        yield self.table(
            'entries',
            SA.Column('dt', SA.DateTime, primary_key=True),
            SA.Column('k', SA.SmallInteger, primary_key=True),
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
                SA.Column('value', SA.String(255)),
            )

    def _entry(self, dt, k):
        col = self.entries.c
        if not self.s('s_entry'):
            cList = [getattr(col, x) for x in self.colNames]
            self.s(
                cList,
                SA.and_(col.dt == SA.bindparam('dt'),
                        col.k == SA.bindparam('k')))
        return self.s().execute(dt=dt, k=k).fetchone()
            
    @transact
    def setEntry(self, dt, k, values):
        """
        Adds a new entry to the database for the specified
        datetime-sequence combination dt-k. See my colNames attribute
        for the six values you need to supply.

        Returns a deferred that fires with True if a new entry was
        already present with the different values, False if it was
        added or already present with the same values.
        """
        def checkExisting(rowValues):
            for k, value in enumerate(rowValues):
                if value != values[k]:
                    return True
            return False

        row = self._entry(dt, k)
        if row:
            return checkExisting(row)
        kw = {'dt': dt, 'k': k}
        for j, name in enumerate(self.colNames):
            kw[name] = values[j]
        self.entries.insert().execute(**kw)
        return False

    @transact
    def setNameValue(self, name, value):
        """
        Get the unique ID for this value in the named table, adding a new
        entry for it there if necessary.
        """
        table = getattr(self, name)
        if not self.s("s_{}".format(name)):
            self.s([table.c.id], table.c.value == SA.bindparam('value'))
        row = self.s().execute(value=value).fetchone()
        if row:
            return row[0]
        rp = table.insert().execute(value=value)
        return rp.lastrowid

    @transact
    def getMaxSequence(self, dt):
        if not self.s('max_sequence'):
            c = self.entries.c
            self.s([SA.func.max(c.k)], c.dt == SA.bindparam('dt'))
        return self.s().execute(dt=dt).fetchone()[0]
    
    @defer.inlineCallbacks
    def setRecord(self, dt, k, record):
        """
        Adds all needed database entries for the supplied record at
        the specified datetime-sequence combination dt-k.

        Returns a deferred that fires with a new value of k if there
        was a conflict with an existing dt-k combination and the new
        value had to be obtained, or with the old k value if not.

        A conflict exists when there is already an entry for the
        specified dt-k combination that matches values than the ones
        in your supplied record.
        """
        if not hasattr(self, 'cm'):
            self.cacheSetup()
        values = [record[x] for x in ('http', 'was_rd', 'ip')]
        for name in self.indexedValues:
            valueDict = self.cachedValues[name]
            value = record[name]
            if self.cm.check(name, value) and value in valueDict:
                # Cached ID
                ID = valueDict[value]
            else:
                # Get ID from DB for value
                ID = yield self.setNameValue(name, value)
                discardedValue = self.cm.set(name, value)
                if discardedValue in valueDict:
                    del valueDict[discardedValue]
                valueDict[value] = ID
            values.append(ID)
        wasPresent = yield self.setEntry(dt, k, values)
        if wasPresent:
            # Need to get a new sequence number for this entry
            maxSequence = yield self.getMaxSequence(dt)
            k = maxSequence + 1
            yield self.setEntry(dt, k, values)
        defer.returnValue(k)

    @transact
    def getRecord(self, dt, k):
        """
        Returns a (deferred) dict containing the record for the specified
        datetime-sequence combination dt-k.
        """
        result = {}
        row = list(self._entry(dt, k))
        for j, name in enumerate(self.directValues):
            result[name] = row[j]
        for j, name in enumerate(self.indexedValues):
            ID = row[j+3]
            cols = getattr(getattr(self, name), 'c')
            for sh in self.selectorator(cols.value):
                sh.where(cols.id == ID)
            result[name] = sh().fetchone()[0]
        return result

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
    def hits(self, year, month, vhost):
        """
        Returns the number of visitors (unique IP addresses) during the
        specified year and month for a particular vhost.
        """
        # TODO

    @transact
    def hitsForIP(self, ip):
        """
        Returns the number of entries for the specified IP address
        """
        cols = self.entries.c
        for sh in self.selectorator(SA.func.count(cols.http)):
            sh.where(cols.ip == ip)
        return sh().fetchone()[0]


                
                
            
