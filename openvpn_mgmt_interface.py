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

from datetime import datetime
from semantic_version import Version as semver
import string
from ipaddress import ip_address
from collections import deque
import re

from logging_utils import debug, info, warning
from management_connection import ManagementConnection
from geoip_wrapper import GeoIPWrapper


def before_openvpn_2_4(version):
    return semver('2.4.0') >= version


def get_date(date_string, uts=False):
    if not uts:
        return datetime.strptime(date_string, "%a %b %d %H:%M:%S %Y")
    else:
        return datetime.fromtimestamp(float(date_string))


class BaseParser(object):
    def __init__(self, data, split_char, debug):
        self.__lines = data.splitlines()
        self.__split_char = split_char
        self.__lines_iteator = iter(self.__lines)
        self.__current_fields = None
        self.__debug = debug

    def _next_line(self):
        self.__current_fields = deque(next(self.__lines_iteator).split(self.__split_char))
        if self.__debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(self.__current_fields))

    def _get_field(self, field_index):
        return self.__current_fields[field_index]

    def _get_fields(self):
        return self.__current_fields


def ClientStatusParser(BaseParser):

    def __init__(self, data, debug=False):
        BaseParser.__init__(self, data, ',', debug=debug)

    def parse(self):
        client_session = {}
        while True:
            self._next_line()

            if self._get_field(0).startswith('END'):
                break
            elif self._get_field(0) == 'TUN/TAP read bytes':
                client_session['tuntap_read'] = int(self._get_field(1))
            elif self._get_field(0) == 'TUN/TAP write bytes':
                client_session['tuntap_write'] = int(self._get_field(1))
            elif self._get_field(0) == 'TCP/UDP read bytes':
                client_session['tcpudp_read'] = int(self._get_field(1))
            elif self._get_field(0) == 'TCP/UDP write bytes':
                client_session['tcpudp_write'] = int(self._get_field(1))
            elif self._get_field(0) == 'Auth read bytes':
                client_session['auth_read'] = int(self._get_field(1))

        return {'Client': client_session}


class ServerStatusParser(BaseParser):

    def __init__(self, data, version, gi, debug=False):
        BaseParser.__init__(self, data, '\t', debug=debug)
        self.__version = version
        self.__gi = gi
        self.__sessions = {}

    def parse(self):
        self._next_line()
        while True:
            if self._get_field(0).startswith('END'):
                break
            elif self._get_field(0).startswith('TITLE') or \
                    self._get_field(0).startswith('GLOBAL') or \
                    self._get_field(0).startswith('TIME'):
                self._next_line()
            elif self._get_field(0) == 'HEADER' and self._get_field(1) == 'CLIENT_LIST':
                self.parse_client_list()
            elif self._get_field(0) == 'HEADER' and self._get_field(1) == 'ROUTING_TABLE':
                self.parse_routing_table()
            else:
                self._next_line()

        return self.__sessions

    def parse_client_list(self,):
        while True:
            self._next_line()
            if self._get_field(0) != 'CLIENT_LIST':
                return

            session = self.parse_client_list_entry(self._get_fields())
            self.__sessions[str(session['local_ip'])] = session

    def parse_client_list_entry(self, parts):
        session = {}
        parts.popleft()
        common_name = parts.popleft()
        remote_str = parts.popleft()
        session['remote_ip'], session['port'] = self.parse_remote_ip(remote_str)

        if session['remote_ip'].is_private:
            session['location'] = 'RFC1918'
        elif session['remote_ip'].is_loopback:
            session['location'] = 'loopback'
        else:
            location_data = self.__gi.record_by_addr(str(session['remote_ip']))
            if location_data is not None:
                session.update(location_data)
            local_ipv4 = parts.popleft()
        if local_ipv4:
            session['local_ip'] = ip_address(local_ipv4)
        else:
            session['local_ip'] = ''
        if self.__version.major >= 2 and self.__version.minor >= 4:
            local_ipv6 = parts.popleft()
            if local_ipv6:
                session['local_ip'] = ip_address(local_ipv6)
        session['bytes_recv'] = int(parts.popleft())
        session['bytes_sent'] = int(parts.popleft())
        parts.popleft()
        session['connected_since'] = get_date(parts.popleft(), uts=True)
        username = parts.popleft()
        if username != 'UNDEF':
            session['username'] = username
        else:
            session['username'] = common_name
        if self.__version.major == 2 and self.__version.minor >= 4:
            session['client_id'] = parts.popleft()
            session['peer_id'] = parts.popleft()
        return session

    def parse_remote_ip(self, remote):
        if remote.count(':') == 1:
            ip, port = remote.split(':')
            port = int(port)
        elif '(' in remote:
            ip, port = remote.split('(')
            port = port[:-1]
            port = int(port)
        else:
            ip = remote
            port = ''
        remote_ip = ip_address(ip)

        return remote_ip, port

    def parse_routing_table(self):
        while True:
            self._next_line()
            if self._get_field(0) != 'ROUTING_TABLE':
                return

            self.parse_routing_table_entry(self._get_fields())

    def parse_routing_table_entry(self, parts):
        local_ip = parts[1]
        remote_ip = parts[3]
        last_seen = get_date(parts[5], uts=True)
        if self.__sessions.get(local_ip):
            self.__sessions[local_ip]['last_seen'] = last_seen
        elif self.is_mac_address(local_ip):
            matching_local_ips = [self.__sessions[s]['local_ip']
                                  for s in self.__sessions if remote_ip ==
                                  self.get_remote_address(self.__sessions[s]['remote_ip'], self.__sessions[s]['port'])]
            if len(matching_local_ips) == 1:
                local_ip = '{0!s}'.format(matching_local_ips[0])
                if self.__sessions[local_ip].get('last_seen'):
                    prev_last_seen = self.__sessions[local_ip]['last_seen']
                    if prev_last_seen < last_seen:
                        self.__sessions[local_ip]['last_seen'] = last_seen
                else:
                    self.__sessions[local_ip]['last_seen'] = last_seen


class StateParser(BaseParser):

    def __init__(self, data, debug=True):
        BaseParser.__init__(self, data, ',', debug=False)

    def parse(self):
        state = {}
        while True:
            self._next_line()
            if self._get_field(0).startswith('END'):
                break
            elif self._get_field(0).startswith('>INFO') or \
                    self._get_field(0).startswith('>CLIENT'):
                continue
            else:
                state['up_since'] = get_date(date_string=self._get_field(0), uts=True)
                state['connected'] = self._get_field(1)
                state['success'] = self._get_field(2)
                if self._get_field(3):
                    state['local_ip'] = ip_address(self._get_field(3))
                else:
                    state['local_ip'] = ''
                if self._get_field(4):
                    state['remote_ip'] = ip_address(self._get_field(4))
                    state['mode'] = 'Client'
                else:
                    state['remote_ip'] = ''
                    state['mode'] = 'Server'
        return state


class OpenvpnMgmtInterface(object):

    def __init__(self, cfg, debug=False):
        self.vpns = cfg.vpns
        self.debug = debug
        self.connections = {}
        self.gi = GeoIPWrapper(cfg.settings['geoip_data'])

    def gather_all_data_and_disconnect(self):
        self.init_all_connections()
        self.collect_metadata()
        self.collect_data()
        self.close_all_connections()

    def disconnect_client(self, vpn_id, client_id, client_ip, client_port):
        if not self.disconnection_allowed(vpn_id):
            return

        connection = self.connections[vpn_id]
        if not connection.is_connected():
            return

        if before_openvpn_2_4(self.vpns[vpn_id]['version']):
            self.send_old_disconnect_command(connection, client_ip, client_port)
        else:
            self.send_new_disconnect_command(connection, client_id)

    def send_new_disconnect_command(self, connection, client_id):
        command = 'client-kill {0!s}'.format(client_id)
        connection.send_command(command)

    def send_old_disconnect_command(self, connection, client_ip, client_port):
        ip = ip_address(client_ip)
        port = int(client_port)
        if ip and port:
            command = 'kill {0!s}:{1!s}'.format(ip, port)
            connection.send_command(command)

    def disconnection_allowed(self, vpn_id):
        vpn = self.vpns[vpn_id]
        return vpn['show_disconnect']

    def init_all_connections(self):
        for vpn_id, vpn in list(self.vpns.items()):
            self.init_connection(vpn)

    def init_connection(self, vpn):
        connection = ManagementConnection(vpn, self.debug)
        connection.connect()
        self.connections[vpn['id']] = connection

    def collect_metadata(self):
        for vpn_id, vpn in list(self.vpns.items()):
            self.collect_vpn_metadata(vpn)

    def collect_data(self):
        for vpn_id, vpn in list(self.vpns.items()):
            self.collect_vpn_data(vpn)

    def collect_vpn_metadata(self, vpn):
        connection = self.connections[vpn['id']]
        if connection.is_connected():
            ver = connection.send_command('version')
            vpn['release'] = self.parse_version(ver)
            vpn['version'] = semver(vpn['release'].split(' ')[1])
            state = connection.send_command('state')
            vpn['state'] = StateParser(state, debug=self.debug).parse()

    def collect_vpn_data(self, vpn):
        connection = self.connections[vpn['id']]
        if connection.is_connected():
            stats = connection.send_command('load-stats')
            vpn['stats'] = self.parse_stats(stats)
            status = connection.send_command('status 3')
            if vpn['state']['mode'] == 'Client':
                vpn['sessions'] = ClientStatusParser(status, debug=self.debug).parse()
            else:
                vpn['sessions'] = ServerStatusParser(status, vpn['version'], self.gi, debug=self.debug).parse()

    def close_all_connections(self):
        for connection in self.connections.values():
            connection.disconnect()

    def parse_stats(self, data):
        stats = {}
        line = re.sub('SUCCESS: ', '', data)
        parts = line.split(',')
        if self.debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
        stats['nclients'] = int(re.sub('nclients=', '', parts[0]))
        stats['bytesin'] = int(re.sub('bytesin=', '', parts[1]))
        stats['bytesout'] = int(re.sub('bytesout=', '', parts[2]).replace('\r\n', ''))
        return stats

    @staticmethod
    def parse_version(data):
        for line in data.splitlines():
            if line.startswith('OpenVPN'):
                return line.replace('OpenVPN Version: ', '')

    @staticmethod
    def is_mac_address(s):
        return len(s) == 17 and \
            len(s.split(':')) == 6 and \
            all(c in string.hexdigits for c in s.replace(':', ''))

    @staticmethod
    def get_remote_address(ip, port):
        if port:
            return '{0!s}:{1!s}'.format(ip, port)
        else:
            return '{0!s}'.format(ip)
