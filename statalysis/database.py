#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
LICENSE
Copyright (C) 2015 Tellectual LLC
"""

from twisted.internet import defer

from sasync.database import transact, SA, AccessBroker

from util import Base


class Transactor(AccessBroker, Base):
    """
    I handle transactions for an efficient database of logfile
    entries.
    """
    directValues = ['http', 'was_rd', 'ip']
    indexedValues = ['vhost', 'url', 'ref', 'ua']
    colNames = directValues +\
               ["id_{}".format(x) for x in indexedValues]

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
        datetime-sequence combination dt-k, complaining if one already
        exists that is different. See my colNames attribute for the
        six values you need to supply.

        Returns a deferred that fires with True if a new entry was
        added or already present with the same values, False if it was
        already present but with different values.
        """
        def checkExisting(rowValues):
            for k, value in enumerate(rowValues):
                if value != values[k]:
                    return False
            return True

        row = self._entry(dt, k)
        if row:
            return checkExisting(row)
        kw = {'dt': dt, 'k': k}
        for j, name in enumerate(self.colNames):
            kw[name] = values[j]
        self.entries.insert().execute(**kw)
        return True

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

    @defer.inlineCallbacks
    def setRecord(self, dt, k, record):
        """
        Adds all needed database entries for the supplied record at
        the specified datetime-sequence combination dt-k.
        """
        values = [record[x] for x in ('http', 'was_rd', 'ip')]
        for name in self.indexedValues:
            value = yield self.setNameValue(name, record[name])
            values.append(value)
        result = yield self.setEntry(dt, k, values)
        defer.returnValue(result)

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
            
                
                
            
