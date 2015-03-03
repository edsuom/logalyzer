#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
LICENSE
Copyright (C) 2015 Tellectual LLC
"""

from twisted.internet import defer
from twisted.internet.defer import waitForDeferred as dw

from sasync.database import transact, SA, AccessBroker

from util import Base


class Transactor(AccessBroker, Base):
    """
    I handle transactions for an efficient database of logfile
    entries.
    """
    indexedValues = ['vhost', 'url', 'ref', 'ua']
    colNames = ['code', 'was_rd', 'ip'] +\
               ["{}_id".format(x) for x in indexedValues]

    @defer.deferredGenerator
    def startup(self):
        yield dw(self.table(
            'entries',
            SA.Column('dt', SA.DateTime, primary_key=True),
            SA.Column('k', SA.SmallInteger, primary_key=True),
            SA.Column('code', SA.SmallInteger, nullable=False),
            SA.Column('was_rd', SA.Boolean, nullable=False),
            SA.Column('ip', SA.String(15), nullable=False),
            
            SA.Column('vhost_id', SA.Integer, nullable=False),
            SA.Column('url_id', SA.Integer, nullable=False),
            SA.Column('ref_id', SA.Integer),
            SA.Column('ua_id', SA.Integer),
        ))
        for name in self.indexedValues:
            yield dw(self.table(
                name,
                SA.Column('id', SA.Integer, primary_key=True),
                SA.Column('value', SA.String(255)),
            ))
    
    @transact
    def setEntry(self, dt, k, values):
        """
        Adds a new entry to the database for the specified
        datetime-sequence combination dt-k, complaining if one already
        exists that is different. See my colNames attribute for the
        six values you need to supply.
        """
        def checkExisting(rowValues):
            for k, value in enumerate(rowValues):
                if value != values[k]:
                    raise Exception(
                        "Differing entry already found at {}: {:d}".format(
                            self.dtFormat(dt), k))
        
        if len(values) != 7:
            raise ValueError(
                "Must specify values for {}".format(
                    ", ".join(self.colNames)))
        col = self.entries.c
        if not self.s('entry_present'):
            cList = [getattr(col, x) for x in self.colNames]
            self.s(
                cList,
                SA.and_(col.dt == SA.bindparam('dt'),
                        col.k == SA.bindparam('k')))
        row = self.s().execute(dt=dt, k=k).fetchone()
        print "ROW", row
        if row:
            checkExisting(row[0])
            return
        kw = {'dt': dt, 'k': k}
        for j, name in enumerate(colNames):
            kw[name] = values[j]
        self.entries.insert().execute(**kw)

    @transact
    def setNameValue(self, name, value):
        """
        Get the unique ID for this value in the named table, adding a new
        entry for it there if necessary.
        """
        table = getattr(self, name)
        if not self.s("{}_present".format(name)):
            self.s([table.c.id], table.c.value == SA.bindparam('value'))
        row = self.s().execute(value=value).fetchone()
        if row:
            return row[0][0]
        rp = table.insert().execute(value=value)
        #import pdb; pdb.set_trace()
        return rp.lastrowid

    @defer.deferredGenerator
    def newRecord(self, dt, k, record):
        """
        Adds all needed database entries for the supplied record at
        the specified datetime-sequence combination dt-k.
        """
        values = [record[x] for x in ('code', 'was_rd', 'ip')]
        for name in self.indexedValues:
            wfd = dw(self.setNameValue(name, record[name]))
            yield wfd
            values.append(wfd.getResult())
        yield dw(self.setEntry(dt, k, values))

    @transact
    def getEntry(self, dt, k):
        E = self.entries
        VH = self.vhost
        VU = self.url
        VR = self.ref
        VA = self.ua
        if not self.s('joined_entries'):
            self.s(
                [E.c.code, E.c.was_rd, E.c.ip,
                 VH.c.value, VU.c.value, VR.c.value, VA.c.value],
                SA.and_(
                    E.c.dt == SA.bindparam('dt'),
                    E.c.k == SA.bindparam('k')),
                from_obj=[
                    E.join(VH, E.c.vhost_id == VH.c.id),
                    E.join(VU, E.c.url_id == VU.c.id),
                    E.join(VR, E.c.ref_id == VR.c.id),
                    E.join(VA, E.c.ua_id == VA.c.id),
                    ]
            )
        row = self.s().execute(dt=dt, k=k).fetchone()
        if row:
            return row[0]
        return None
    
                    
                        


            
            
            
            
