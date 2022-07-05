#!/usr/bin/env python3
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

import argparse
import os
import socket
import string
import sys
import jinja2
from datetime import datetime
from pprint import pformat

from logging import debug, info, warning
from openvpn_mgmt_interface import OpenvpnMgmtInterface
from config_loader import ConfigLoader, is_truthy

def get_args():
    parser = argparse.ArgumentParser(
        description='Display a html page with openvpn status and connections')
    parser.add_argument('-d', '--debug', action='store_true',
                        required=False, default=False,
                        help='Run in debug mode')
    parser.add_argument('-c', '--config', type=str,
                        required=False, default='./openvpn-monitor.conf',
                        help='Path to config file openvpn-monitor.conf')
    return parser.parse_args()


def build_template_environment():
    env = jinja2.Environment(
        loader = jinja2.FileSystemLoader('./templates'),
        extensions = ["jinja2_humanize_extension.HumanizeExtension"]
    )

    env.globals.update({
        'now': datetime.now,
    })

    return env


def build_template_context(cfg, monitor, debug=False):
    if debug:
        pretty_vpns = pformat((dict(monitor.vpns)))
        debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))
    return {
        'site': cfg.settings.get('site', 'Example'),
        'vpns': list(monitor.vpns.items()),
        'maps': is_truthy(cfg.settings.get('maps', False)),
        'maps_height': cfg.settings.get('maps_height', 500),
        'latitude': cfg.settings.get('latitude', 40.72),
        'longitude': cfg.settings.get('longitude', -74),
        'datetime_format': cfg.settings.get('datetime_format')
    }

env = build_template_environment()
def view(template_name):
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(*args, **kwargs):
            response = view_func(*args, **kwargs)
            if isinstance(response, dict):
                template = env.get_or_select_template(template_name)
                return template.render(**response)
            else:
                return response

        return wrapper

    return decorator


def monitor_wsgi(config, debug=False):

    owd = os.getcwd()
    if owd.endswith('site-packages') and sys.prefix != '/usr':
        # virtualenv
        image_dir = owd + '/../../../share/openvpn-monitor/'
    else:
        image_dir = ''

    app = Bottle()

    @app.hook('before_request')
    def strip_slash():
        request.environ['PATH_INFO'] = request.environ.get('PATH_INFO', '/').rstrip('/')
        if debug:
            debug(pformat(request.environ))

    @app.route('/', method='GET')
    @view('openvpn-monitor.html.j2')
    def get_slash():
        cfg = ConfigLoader(config)
        monitor = OpenvpnMgmtInterface(cfg, debug=debug)

        return build_template_context(cfg, monitor)

    @app.route('/', method='POST')
    @view('openvpn-monitor.html.j2')
    def post_slash():
        cfg = ConfigLoader(config)
        vpn_id = request.forms.get('vpn_id')
        ip = request.forms.get('ip')
        port = request.forms.get('port')
        client_id = request.forms.get('client_id')
        monitor = OpenvpnMgmtInterface(cfg, debug=debug, vpn_id=vpn_id, ip=ip, port=port, client_id=client_id)

        return build_template_context(cfg, monitor)

    @app.route('/<filename:re:.*\.(jpg|png)>', method='GET')
    def get_images(filename):
        return static_file(filename, image_dir)

    return app


def running_as_app():
    return __name__ != '__main__'

def fix_working_directory():
    if __file__ != 'openvpn-monitor.py':
        os.chdir(os.path.dirname(__file__))
        sys.path.append(os.path.dirname(__file__))


if running_as_app():
    from bottle import Bottle, response, request, static_file, functools
    fix_working_directory()
    application = monitor_wsgi('./openvpn-monitor.conf')
else:
    args = get_args()
    template = env.get_template('openvpn-monitor.html.j2')
    cfg = ConfigLoader(args.config, debug=args.debug)
    monitor = OpenvpnMgmtInterface(cfg, debug=args.debug)
    print(template.render(build_template_context(cfg, monitor)))
