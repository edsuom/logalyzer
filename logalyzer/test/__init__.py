# statalysis:
# A powerful logfile analysis tool
#
# Copyright (C) 2015 by Edwin A. Suominen, http://edsuom.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
Unit tests for statalysis
"""

import sys, os.path

# Ensure that the package under test and its modules can all be imported by
# name only
packagePath = os.path.dirname(__file__)
for k in xrange(2):
    packagePath = os.path.dirname(packagePath)
    if packagePath not in sys.path:
	sys.path.insert(0, packagePath)
