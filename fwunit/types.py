# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# special types that are used within the Pickle file

from fwunit.ip import IPSet, IP
from collections import namedtuple
import itertools

Rule = namedtuple('Rule', ['src', 'dst', 'app', 'name'])
FWRule = namedtuple('FWRule', ['src', 'dst', 'app', 'name', 'permission'])
RulesByApp = namedtuple('RulesByApp', ['permit_rules', 'deny_rules', 'permit_deny_rules'])

ModifiedFlow = namedtuple('ModifiedFlow', ['src', 'dst', 'new_name', 'old_name'])

FWRuleSequence = namedtuple('FWRuleSequence', ['src', 'dst', 'app', 'name', 'permission', 'sequence'])  # used
RuleNameMappingEntry = namedtuple('RuleNameMappingEntry', ['src', 'dst', 'sequence', 'priority', 'name'])  # used

tcp_all = ['tcp-'+str(i) for i in xrange(1, 65536)]
udp_all = ['udp-'+str(i) for i in xrange(1, 65536)]


def default_value():
    return []


def ipset_to_jsonable(ipset):
    return [str(pfx) for pfx in ipset]


def to_jsonable(rules):
    return [{'src': ipset_to_jsonable(r.src),
             'dst': ipset_to_jsonable(r.dst),
             'app': r.app,
             'name': r.name}
            for r in itertools.chain(*rules.itervalues())]


def ipset_from_jsonable(ipset, _cache={}):
    ipset = tuple(ipset)
    if ipset not in _cache:
        _cache[ipset] = rv = IPSet([IP(pfx) for pfx in ipset])
        return rv
    return _cache[ipset]


def from_jsonable(rules):
    by_app = {}
    for d in rules:
        r = Rule(src=ipset_from_jsonable(d['src']),
                 dst=ipset_from_jsonable(d['dst']),
                 app=d['app'],
                 name=d['name'])
        app = r.app
        by_app.setdefault(app, []).append(r)
    return by_app


def to_jsonable_custom(rules):
    return [{'src': ipset_to_jsonable(r.src),
             'dst': ipset_to_jsonable(r.dst),
             'app': r.app,
             'name': r.name,
             'permission': r.permission}
            for r in itertools.chain(*rules.itervalues())]


def from_jsonable_custom(rules):
    by_app = {}
    for d in rules:
        r = FWRule(src=ipset_from_jsonable(d['src']),
                   dst=ipset_from_jsonable(d['dst']),
                   app=d['app'],
                   name=d['name'],
                   permission=d['permission'])
        app = r.app
        by_app.setdefault(app, []).append(r)
    return by_app
