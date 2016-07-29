# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .parse import Firewall
from .process import policies_to_rules
from fwunit import common
import logging


def run(policies_path, address_books_path, apps_dir, zones_path=None, routes_path=None):
    app_map = common.ApplicationMap({})
    firewall = Firewall(policies_path, address_books_path, zones_path, routes_path)
    return policies_to_rules(app_map, firewall, apps_dir)
