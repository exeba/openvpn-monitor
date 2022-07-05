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

try:
    import GeoIP as geoip1
    geoip1_available = True
except ImportError:
    geoip1_available = False

try:
    from geoip2 import database
    from geoip2.errors import AddressNotFoundError
    geoip2_available = True
except ImportError:
    geoip2_available = False

from logging import debug, info, warning


class GeoIPWrapper(object):

    def __init__(self, data_file):
        self.__data_file = data_file
        self.__geoip_version = None
        self.__gi = None
        try:
            if self.__data_file.endswith('.mmdb') and geoip2_available:
                self.__gi = database.Reader(self.__data_file)
                self.__geoip_version = 2
            elif self.__data_file.endswith('.dat') and geoip1_available:
                self.__gi = geoip1.open(self.__data_file, geoip1.GEOIP_STANDARD)
                self.__geoip_version = 1
            else:
                warning('No compatible geoip1 or geoip2 data/libraries found.')
        except IOError:
            warning('No compatible geoip1 or geoip2 data/libraries found.')

    def record_by_addr(self, addr):
        try:
            return self.__record_by_addr(addr)
        except SystemError:
            return None

    def __record_by_addr(self, addr):
        if self.__geoip_version == 2:
            return self.__record_by_addr_v2(addr)
        elif self.__geoip_version == 1:
            return self.__record_by_addr_v1(addr)
        else:
            return None

    def __record_by_addr_v1(self, addr):
        gir = self.__gi.record_by_addr(addr)
        if gir is None:
            return None

        return {
            'location': gir['country_code'],
            'region': gir['region'],
            'city': gir['city'],
            'country': gir['country_name'],
            'longitude': gir['longitude'],
            'latitude': gir['latitude'],
        }

    def __record_by_addr_v2(self, addr):
        try:
            gir = self.__gi.city(addr)

            return {
                'location': gir.country.iso_code,
                'region': gir.subdivisions.most_specific.iso_code,
                'city': gir.city.name,
                'country': gir.country.name,
                'longitude': gir.location.longitude,
                'latitude': gir.location.latitude,
            }
        except AddressNotFoundError:
            return None
