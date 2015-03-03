#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path
from datetime import datetime as dt
import marshal

import ipcalc
from twisted.internet import defer
from twisted.python import failure

import testbase as tb

import writer

ip1 = "171.127.9.141"
ip2 = "32.132.214.244"

RECORDS = {
    dt(2015, 2, 20, 12, 2, 49): [
        {'vhost': "foo.com", 'ip': ip1, 'code': 200,
         'url': "/", 'ref': "-", 'ua': "-"},
        {'vhost': "foo.com", 'ip': ip1, 'code': 200,
         'url': "/image.png", 'ref': "-", 'ua': "-"}],
    dt(2015, 3, 2, 21, 17, 16): [
        {'vhost': "bar.com", 'ip': ip2, 'code': 404,
         'url': "/", 'ref': "-", 'ua': "-"}],
    }

vhosts = ["foo.com", "foo.com", "bar.com"]
ips = [ip1, ip1, ip2]


class TestWriter(tb.TestCase):
    def setUp(self):
        self.w = writer.Writer()
        self.data = []

    def _setupFOO(self, filePath):
        self.data.append(filePath)
        return self._sd

    def _writeFOO(self, dt, k, record):
        self.data.append([dt, k, record])

    def _sd(self):
        self.data.append("SD")
    
    def test_ipToLong(self):
        for ip in (ip1, ip2):
            self.assertEqual(self.w.ipToLong(ip), long(ipcalc.IP(ip)))

    def test_makeRow(self):
        for theseRecords in RECORDS.values():
            for thisRecord in theseRecords:
                row = self.w.makeRow(thisRecord)
                self.assertEqual(row[0], thisRecord['vhost'])
                self.assertEqual(row[1], thisRecord['ip'])
                self.assertEqual(row[2], thisRecord['code'])
                self.assertEqual(row[3], thisRecord['url'])
                self.assertEqual(row[4], thisRecord['ref'])
                self.assertEqual(row[4], thisRecord['ua'])
                self.assertEqual(len(row), 6)

    def test_recordator(self):
        kValues = [0, 1, 0]
        for j, stuff in enumerate(self.w.recordator(RECORDS)):
            dt, k, record = stuff
            self.assertEqual(k, kValues[j])
            self.assertEqual(record['vhost'], vhosts[j])
            self.assertEqual(record['ip'], ips[j])

    def test_write_basic(self):
        def done(null):
            self.assertEqual(self.data[0], "file.foo")
            self.assertEqual([x[0] for x in self.data[1:-1]], vhosts)
            self.assertEqual(self.data[-1], "SD")
        
        self.w._setupFOO = self._setupFOO
        self.w._writeFOO = self._writeFOO
        self.w.writeTypes['FOO'] = "file.foo"
        return self.w.write(RECORDS)

    def test_write_csv(self):
        def done(null):
            self.assertTrue(os.path.isfile(csvPath))
            print "\nCSV file:\n"
            with open(csvPath, 'rb') as fh:
                for k, line in enumerate(fh):
                    print k, line.strip()
            
        csvPath = tb.tempFiles(tb.fileInModuleDir("file.csv"))[0]
        self.w.writeTypes['CSV'] = csvPath
        return self.w.write(RECORDS).addCallback(done)

    def test_write_pyo(self):
        def done(null):
            self.assertTrue(os.path.isfile(pyoPath))
            lists = []
            with open(pyoPath, 'rb') as fh:
                while True:
                    try:
                        obj = marshal.load(fh)
                    except:
                        obj = None
                    if obj is None:
                        break
                    lists.append(obj)
            self.assertEqual(len(lists), 3)
            self.assertEqual([x[2]['vhost'] for x in lists], vhosts)
            self.assertEqual([x[2]['ip'] for x in lists], ips)
            
        pyoPath = tb.tempFiles(tb.fileInModuleDir("file.pyo"))[0]
        self.w.writeTypes['PYO'] = pyoPath
        return self.w.write(RECORDS).addCallback(done)

        
