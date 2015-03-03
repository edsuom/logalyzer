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
    colNames = ['http', 'was_rd', 'ip'] +\
               ["id_{}".format(x) for x in indexedValues]

    @defer.deferredGenerator
    def startup(self):
        yield dw(self.table(
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

        Returns a deferred that fires with True if a new entry was
        added or already present with the same values, False if it was
        already present but with different values.
        """
        def checkExisting(rowValues):
            for k, value in enumerate(rowValues):
                if value != values[k]:
                    return False
            return True

        col = self.entries.c
        if not self.s('entry_present'):
            cList = [getattr(col, x) for x in self.colNames]
            self.s(
                cList,
                SA.and_(col.dt == SA.bindparam('dt'),
                        col.k == SA.bindparam('k')))
        row = self.s().execute(dt=dt, k=k).fetchone()
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
        if not self.s("{}_present".format(name)):
            self.s([table.c.id], table.c.value == SA.bindparam('value'))
        row = self.s().execute(value=value).fetchone()
        if row:
            return row[0]
        rp = table.insert().execute(value=value)
        return rp.lastrowid

    @defer.deferredGenerator
    def newRecord(self, dt, k, record):
        """
        Adds all needed database entries for the supplied record at
        the specified datetime-sequence combination dt-k.
        """
        values = [record[x] for x in ('http', 'was_rd', 'ip')]
        for name in self.indexedValues:
            wfd = dw(self.setNameValue(name, record[name]))
            yield wfd
            values.append(wfd.getResult())
        yield dw(self.setEntry(dt, k, values))

    @transact
    def getEntry(self, dt, k):
        """
        Doesn't work, but not needed except for testing, for now:

        Failure: sqlalchemy.exc.OperationalError: (OperationalError)
        ambiguous column name: entries.http u'SELECT entries.http AS
        entries_http, entries.was_rd AS entries_was_rd, entries.ip AS
        entries_ip, vhost.value AS vhost_value, url.value AS
        url_value, ref.value AS ref_value, ua.value AS ua_value \nFROM
        entries JOIN vhost ON entries.id_vhost = vhost.id, entries
        JOIN url ON entries.id_url = url.id, entries JOIN ref ON
        entries.id_ref = ref.id, entries JOIN ua ON entries.id_ua =
        ua.id \nWHERE entries.dt = ? AND entries.k = ?' ('2015-02-20
        12:02:49.000000', 0)

        """
        E = self.entries
        VH = self.vhost
        VU = self.url
        VR = self.ref
        VA = self.ua
        if not self.s('joined_entries'):
            self.s(
                [E.c.http, E.c.was_rd, E.c.ip,
                 VH.c.value, VU.c.value, VR.c.value, VA.c.value],
                SA.and_(
                    E.c.dt == SA.bindparam('dt'),
                    E.c.k == SA.bindparam('k')),
                from_obj=[
                    E.join(VH, E.c.id_vhost == VH.c.id),
                    E.join(VU, E.c.id_url == VU.c.id),
                    E.join(VR, E.c.id_ref == VR.c.id),
                    E.join(VA, E.c.id_ua == VA.c.id),
                    ],
                use_labels = True,
            )
        return self.s().execute(dt=dt, k=k).fetchone()

            
            
