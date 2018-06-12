## logalyzer
*Web server HTTP access log parsing, filtering, and SQL database storage.*

* [API Docs](http://edsuom.com/logalyzer/logalyzer.html)
* [PyPI Page](https://pypi.python.org/pypi/logalyzer/)
* [Project Page](http://edsuom.com/logalyzer.html) at **edsuom.com**
* *See also* [sAsync](http://edsuom.com/sAsync.html) and [AsynQueue](http://edsuom.com/AsynQueue.html).

*logalyzer* parses your bloated HTTP access logs to extract the info
you want about hits from (hopefully) real people instead of just the
endless stream of hackers and bots that passes for web traffic
nowadays. It stores the info in a relational database where you can
access it using all the power of SQL.

This package uses the power of your multicore CPU with
[Twisted](https://twistedmatrix.com/trac/),
[AsynQueue](http://edsuom.com/AsynQueue.html), and
[sAsync](http://edsuom.com/sAsync.html) to process log files
concurrently and fast. Duplicate entries are ignored, so you don't
need to fret about redundancies in your logfiles. (It happens.)  The
filtering goes forwards and backwards; once an entry has been
determined to come from a bad actor, all log entries from that IP
address are purged and ignored.

### Usage

After you install the package with `pip install logalyzer`, you will
have a new command `la` at your disposal that runs logalyzer. You'll
also need to set up a new SQL database for the parsed and filtered
access log data.

Let's say you use MySQL and call your new database *logs*, with a
non-privileged user *logalyzer*. Then you'll execute this command from
a directory containing your access.log.XX files (there will be numerous
log files due to your web server rotating them when *access.log* gets
too big):

    la -g mysql://logalyzer@localhost/logs
    
The `-g` option is to use the ncurses GUI. You don't need the GUI, but
it makes it a lot easier to visualize what's going on.

The first time you run the command, it will create a rules directory
in your home directory. The default is `~/.logalyzer`, but you can
specify a different one with the `-d` option.

Logalyzer will read each of your access.log files in the directory
you're in (or one you specify with a second command-line argument
after the database URL) and parse and filter its contents, saving any
non-bogus new stuff to the database. It will read rotated logfiles
that have been compressed with `.gz` extensions, and ignore content
that isn't compliant with the standard HTTP logfile format. (It does
forgive the weirdness added to logs by a webserver built with Twisted,
like my own.)

The rules directory contains files specifying filters for excluding
uninteresting and malicious stuff that everyone's web access log files
is full of nowadays. Look at the *README.txt* file in the rules
directory to see what extensions are used with each kind of file, and
whether the filtering just ignores the entries or adds the IP address
of the client making the entries to a block list.

Save the block list to a file by specifying a filename with the `-s`
option. You use it to create an IPTABLES ruleset blocking the bad
actors from ever reaching your site again. (Beware, though; that is
like playing whack-a-mole.)


### Database

Logalyzer evaluates each entry in the logfiles to see if it is
interesting and not malicious, and, if so, checks to see if the entry
has already been added in the database. If it's not there already, it
adds a record to the *entries* table of the database, with the
timestamp of the web access, the IP address, the HTTP code, a Boolean
value indicating if the access was a redirect, and four integer ID
codes that key to four other tables with more info about the web
access.

The four other tables are *vhost*, containing the virtual host
requested, *url* containing the URL requested, *ref* containing the
referrer string, and the *ua* containing the user-agent string. Look
through the example SQL files included with the source distribution
(accessible online
[here](https://github.com/edsuom/logalyzer/tree/master/sql-examples))
to see how these tables work together with the power of a relational
database.

Here's one example, `unique-visitors-by-url-recent.sql`:

    SELECT year(e.dt) YR, month(e.dt) MO, count(distinct e.ip) N, url.value URL
    FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
    INNER JOIN url ON e.id_url = url.id
    WHERE vhost.value REGEXP '^(www\.)?edsuom\.com'
     AND e.http != 404
     AND url.value NOT REGEXP '\.(jpg|png|gif|ico|css)'
    GROUP BY URL, YR, MO
    HAVING N > 1
    ORDER BY YR DESC, MO DESC, N DESC;

Obviously, change *edsuom.com* to one of your virtual hosts. This SQL
query will show you how many unique IP addresses were fetching the
most popular URLs on that virtual host, for each year and month.


### Filtering

If you see bot garbage getting through and polluting your logs with
some new attempt at an exploit, just add a rule for it to your rules
lists, starting with what *logalyzer* comes prepackaged with. The next
time you run it, those entries will get purged as well and the IP
addresses added to the blocklist.


### License

Copyright (C) 2015, 2017-2018 by Edwin A. Suominen,
<http://edsuom.com/>:

    See edsuom.com for API documentation as well as information about
    Ed's background and other projects, software and otherwise.
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the
    License. You may obtain a copy of the License at
    
      http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an "AS
    IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
    express or implied. See the License for the specific language
    governing permissions and limitations under the License.
