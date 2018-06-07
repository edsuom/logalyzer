RULE FILES

Put plain text files in this directory match a rule below and ignore
junk entries from your logfiles. The IP addresses of HTTP clients
matching certain rules have all their logfile entries ignored and any
entries that happened to be previously stored purged from the
database. Those IP addresses are added to a blocklist that you can
export to a file with the logalyzer --save option.

The rules are matched in the order listed.

Because logalyzer automatically populates your rules directory with
example files (and this README.txt) as needed every time it gets run,
it will just replace any that you delete. If you don't want to have a
file at all (e.g., no hackers.ip), just remove all its entries or do
something like this:

cp /dev/null ~/.logalyzer/hackers.ip

You can of course add your own files and delete them at any time.



FILE EXTENSION: .ip
ADDED TO BLOCK LIST: No
-------------------------------------------------------------------------------
Individual IP addresses of HTTP clients you want to ignore. These
aren't subnet blocks, but individual 32-bit IP addresses in
dotted-quad format. The example file hackers.ip lists a few
undesirables I've encountered in my logfiles.

Fast, but beware that relying on it is like trying to control
mosquitos with a flyswatter. Mostly for really egregious cases.



FILE EXTENSION: .url
ADDED TO BLOCK LIST: Yes
-------------------------------------------------------------------------------
Efficiently checks for bots that are seen in logs doing hacker-type
things, and should get blocked. The example file hackers.url weeds out
shady crap like attempts to access admin pages.

Note that my own site edsuom.com does not use any admin pages; it's a
static HTML site, with updates compiled and pushed to the server via
SSH. So I can get away with blocking anyone who tries to access such
pages. You might not be able to do that, in which case you'll need to
adjust the example file.



FILE EXTENSION: .ref
ADDED TO BLOCK LIST: Yes
-------------------------------------------------------------------------------
Efficiently checks for referrers that are clearly logspammers, and
should get blocked. Seriously, "buttons-for-website"? The example file
is logspam.ref.



FILE EXTENSION: .ua
ADDED TO BLOCK LIST: No
-------------------------------------------------------------------------------
Efficiently checks for user agents that clog up your logs, though they
shouldn't be blocked. Example file has some good guys and a couple
that are questionable.



FILE EXTENSION: .vhost
ADDED TO BLOCK LIST: Yes
-------------------------------------------------------------------------------
If you have a virtual host that nobody benign would be trying to
access but you see scumbags trying to (like admin.yoursite.com), add
it to this list. No example file provided.



FILE EXTENSION: .net
ADDED TO BLOCK LIST: No
-------------------------------------------------------------------------------
The last and by FAR the most time-consuming check is for excluded
networks to ignore (but not block). Only done if all other checks have
passed. Use your .net rules to avoid getting bogged down with logfile
analysis of requests from places where you just KNOW it's not an
actual person browsing your site.

Downloading some lists from http://www.wizcrafts.net/ for China,
Russia, etc. and putting them into china.net, russia.net, etc. files
might clean up your logs considerably. A truncated china.net file is
included as an example, but you'd want a full-length one directly from
the wizcrafts site.

You might consider putting those blocklists into IPTABLES and just
block places that show little respect for copyright and people's
privacy and human rights. Then you won't have their bots and scrapers
bogging down your server in addition to not polluting your logs.

