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

import configparser
from collections import OrderedDict
import sys

from logging import debug, info, warning


def is_truthy(s):
    return s in ['True', 'true', 'Yes', 'yes', True]


class ConfigLoader(object):

    def __init__(self, config_file, debug=False):
        self.settings = {}
        self.debug = debug
        self.vpns = OrderedDict()
        config = configparser.RawConfigParser()
        contents = config.read(config_file)

        if not contents and config_file == './openvpn-monitor.conf':
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            if sys.prefix == '/usr':
                conf_path = '/etc/'
            else:
                conf_path = sys.prefix + '/etc/'
            config_file = conf_path + 'openvpn-monitor.conf'
            contents = config.read(config_file)

        if contents:
            info('Using config file: {0!s}'.format(config_file))
        else:
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            self.load_default_settings()

        for section in config.sections():
            if section.lower() == 'openvpn-monitor':
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)

    def load_default_settings(self):
        info('Using default settings => localhost:5555')
        self.settings = {'site': 'Default Site',
                         'maps': 'True',
                         'geoip_data': '/usr/share/GeoIP/GeoIPCity.dat',
                         'datetime_format': '%d/%m/%Y %H:%M:%S'}
        self.vpns['Default VPN'] = {'name': 'default',
                                    'host': 'localhost',
                                    'port': '5555',
                                    'password': '',
                                    'show_disconnect': False}

    def parse_global_section(self, config):
        global_vars = ['site', 'logo', 'latitude', 'longitude', 'maps', 'maps_height', 'geoip_data', 'datetime_format']
        for var in global_vars:
            try:
                self.settings[var] = config.get('openvpn-monitor', var)
            except configparser.NoSectionError:
                # backwards compat
                try:
                    self.settings[var] = config.get('OpenVPN-Monitor', var)
                except configparser.NoOptionError:
                    pass
            except configparser.NoOptionError:
                pass
        if self.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(self.settings))

    def parse_vpn_section(self, config, section):
        self.vpns[section] = {}
        vpn = self.vpns[section]
        options = config.options(section)
        for option in options:
            try:
                vpn[option] = config.get(section, option)
                if vpn[option] == -1:
                    warning('CONFIG: skipping {0!s}'.format(option))
            except configparser.Error as e:
                warning('CONFIG: {0!s} on option {1!s}: '.format(e, option))
                vpn[option] = None
        vpn['show_disconnect'] = is_truthy(vpn.get('show_disconnect', False))
        if self.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))
