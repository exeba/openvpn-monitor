# -*- coding: utf-8 -*-

# Copyright 2011 VPAC <http://www.vpac.org>
# Copyright 2012-2019 Marcus Furlong <furlongm@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 only.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

import sys

def info(*objs):
    print("INFO:", *objs, file=sys.stderr)


def warning(*objs):
    print("WARNING:", *objs, file=sys.stderr)


def debug(*objs):
    print("DEBUG:\n", *objs, file=sys.stderr)
