# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import itertools
from fwunit.ip import IP, IPSet, IPPairs
from fwunit.types import Rule, FWRuleSequence, RuleNameMappingEntry, default_value, tcp_all, udp_all
from .parse import Policy
from fwunit.common import simplify_rules
from logging import getLogger
from collections import defaultdict
from multiprocessing import Pool
import pickle
import os

logger = getLogger(__name__)


def policies_to_rules(app_map, firewall, apps_dir):
    """Process the data in a parse.Firewall instance into a list of non-overlapping
    Rule instances, suitable for queries"""
    interface_ips = process_interface_ips(firewall.routes)
    zone_nets = process_zone_nets(firewall.zones, interface_ips)
    policies_by_zone_pair = process_policies_by_zone_pair(firewall.policies)
    attached_networks = process_attached_networks(firewall.routes)
    policies_by_zone_pair = process_attached_network_policies(
        policies_by_zone_pair, zone_nets, attached_networks)
    addrbooks_per_zone, global_addrbook = process_address_books_per_zone(
        firewall.zones, firewall.address_books)
    src_per_policy, dst_per_policy = process_address_sets_per_policy(
        firewall.zones, policies_by_zone_pair, addrbooks_per_zone, global_addrbook)
    return process_rules(app_map, firewall.policies, zone_nets,
                         policies_by_zone_pair, src_per_policy,
                         dst_per_policy, apps_dir)


def process_interface_ips(routes):
    # figure out the IPSet routed via each interface, by starting with the most
    # specific and only considering IP space not already allocated to an
    # interface.  This has the effect of leaving a "swiss cheese" default route
    # containing all IPs that aren't routed by a more-specific route.
    logger.info("calculating interface IP ranges")
    routes = routes[:]
    routes.sort(key=lambda r: -r.destination.prefixlen())
    matched = IPSet()
    interface_ips = {}
    for r in routes:
        destset = IPSet([r.destination])
        if r.interface and not r.reject:
            interface_ips[r.interface] = interface_ips.get(
                r.interface, IPSet()) + (destset - matched)
        # consider the route matched even if it didn't have an
        # interface or is a blackhole
        matched = matched + destset
    return interface_ips


def process_attached_networks(routes):
    # return a list of networks to which this firewall is directly connected,
    # so there is no "next hop".
    logger.info("calculating attached networks")
    networks = [IPSet([r.destination]) for r in routes if r.is_local]
    return networks


def process_zone_nets(zones, interface_ips):
    # figure out the IPSet of IPs for each security zone.  This makes the
    # assumption (just like RFP) that each IP will communicate on exactly one
    # firewall interface.  Each interface is in exactly one zone, so this means
    # that each IP is in exactly one zone.
    logger.info("calculating zone IP ranges")
    zone_nets = {}
    for zone in zones:
        net = IPSet()
        for itfc in zone.interfaces:
            try:
                net += interface_ips[itfc]
            except KeyError:
                # if the interface doesn't have any attached subnet, continue on
                # (this can happen for backup interfaces, for example)
                pass
        zone_nets[zone.name] = net
    return zone_nets


def process_policies_by_zone_pair(policies):
    logger.info("tabulating policies by zone")
    policies_by_zone_pair = {}
    for pol in policies:
        policies_by_zone_pair.setdefault(
            (pol.from_zone, pol.to_zone), []).append(pol)
    return policies_by_zone_pair


def process_attached_network_policies(policies_by_zone_pair, zone_nets, attached_networks):
    # include a full permit policy for traffic within each attached network,
    # since such traffic will flow within that network and not through the
    # firewall.
    for (from_zone, to_zone), zpolicies in policies_by_zone_pair.iteritems():
        if from_zone is None or from_zone != to_zone:
            continue
        zone_net = zone_nets[from_zone]
        for att in attached_networks:
            if att & zone_net:
                pfx = str(att.prefixes[0])
                pol = Policy()
                pol.name = "local-%s" % pfx
                pol.from_zone = from_zone
                pol.to_zone = to_zone
                pol.enabled = True
                pol.sequence = -1
                # these lists ordinarily contain address names, but these are
                # IPSets.  This is handled in process_adddress_sets_per_policy.
                pol.source_addresses = [att]
                pol.destination_addresses = [att]
                pol.applications = ['any']
                pol.action = 'permit'
                zpolicies.insert(0, pol)
    # this has been modified in place:
    return policies_by_zone_pair


def process_address_books_per_zone(zones, address_books):
    # Juniper has three types of address books:
    # - zone address books (embedded in the zone)
    # - named address books ("attached" to zones)
    # - global address book (implicit in all zones)
    # Juniper actually only allows two to be in use on a single system, but
    # for simplicity we handle all three.  The precedence is as given above.
    # XXX: note that address-sets are resolved when parsing; this may not
    # be an accurate representation of how addresses are resolved
    logger.info("compiling address books per zone")
    by_zone = {}

    # apply zone address books
    for zone in zones:
        by_zone[zone.name] = [zone.addresses]

    # apply attached address books
    global_addrbook = {}
    for addrbook in address_books:
        if addrbook.name == 'global':
            global_addrbook = addrbook.addresses
            continue
        for zone in addrbook.attaches:
            by_zone[zone].append(addrbook.addresses)

    # apply the global book, if we found one
    if global_addrbook:
        for bz in by_zone.itervalues():
            bz.append(global_addrbook)

    # now flatten each into a single dictionary
    flattened_by_zone = {}
    for zone, books in by_zone.iteritems():
        flattened = {}
        for addrs in reversed(books):
            flattened.update(addrs)
        flattened_by_zone[zone] = flattened

    return flattened_by_zone, global_addrbook


def get_addr(a, addrbook):
    # if 'a' is a group name, look it up in addrbook, else it is an ip group in CIDR notation
    if a in addrbook:
        return addrbook[a]
    else:
        return IPSet([IP(a)])


def process_address_sets_per_policy(zones, policies_by_zone_pair,
                                    addrbooks_per_zone, global_addrbook):
    logger.info("computing address sets per policy")
    src_per_policy = {}
    dst_per_policy = {}
    for (from_zone, to_zone), zpolicies in policies_by_zone_pair.iteritems():
        from_addrbook = addrbooks_per_zone.get(from_zone, global_addrbook)
        # get_from = lambda a: a if isinstance(a, IPSet) else from_addrbook[a]
        get_from = lambda a: a if isinstance(a, IPSet) else get_addr(a, from_addrbook)
        to_addrbook = addrbooks_per_zone.get(to_zone, global_addrbook)
        # get_to = lambda a: a if isinstance(a, IPSet) else to_addrbook[a]
        get_to = lambda a: a if isinstance(a, IPSet) else get_addr(a, to_addrbook)
        for pol in zpolicies:
            src_per_policy[pol] = sum(
                (get_from(a) for a in pol.source_addresses), IPSet())
            dst_per_policy[pol] = sum(
                (get_to(a) for a in pol.destination_addresses), IPSet())
    return src_per_policy, dst_per_policy


def process_permit_rules_by_app(mapped_app, from_zone, to_zone, zone_nets, zpolicies, src_per_policy, dst_per_policy):
    # for each app, count down the IP pairs that have not matched a
    # rule yet, starting with the zones' IP spaces.  This simulates sequential
    # processing of the policies.
    permit_rules = []
    remaining_pairs = IPPairs(
        (zone_nets[from_zone], zone_nets[to_zone]))
    for pol in zpolicies:
        if mapped_app not in pol.applications and 'any' not in pol.applications:
            continue
        src = src_per_policy[pol]
        dst = dst_per_policy[pol]
        # if the policy is a "permit", add rules for each
        # src/destination pair
        for s, d in remaining_pairs:
            s = s & src
            d = d & dst
            if len(s) and len(d):
                if pol.action == 'permit':
                    permit_rules.append(Rule(s, d, mapped_app, pol.name))
        # regardless, consider this src/dst pair matched
        remaining_pairs = remaining_pairs - IPPairs((src, dst))
        # if we've matched everything, we're done
        if not remaining_pairs:
            break
    return mapped_app, permit_rules


def process_permit_rules_by_app_star(args):
    return process_permit_rules_by_app(*args)


def write_app_to_file(mapped_app, dir_path, permit_rules, rule_name_mapping, permit_deny_rules):
    _dict = {mapped_app: [permit_rules, rule_name_mapping, permit_deny_rules]}
    file_path = os.path.join(dir_path, mapped_app)
    with open(file_path, 'wb') as f:
        pickle.dump(_dict, f)


def write_app_to_file_star(args):
    write_app_to_file(*args)


def file_content_generator(apps_dir, all_apps, app_map, permit_rules_by_app, rule_name_mapping, permit_deny_rules):
    for app in all_apps:
        mapped_app = app_map[app]
        yield mapped_app, apps_dir, permit_rules_by_app[mapped_app], rule_name_mapping[mapped_app], permit_deny_rules[mapped_app]


def content_generator(mapped_apps, from_zone, to_zone, zone_nets, zpolicies, src_per_policy, dst_per_policy):
    for mapped_app in mapped_apps:
        yield mapped_app, from_zone, to_zone, zone_nets, zpolicies, src_per_policy, dst_per_policy


def process_rules(app_map, policies, zone_nets, policies_by_zone_pair,
                  src_per_policy, dst_per_policy, apps_dir):
    logger.info("processing rules")
    # turn policies into a list of Rules (permit only), limited by zone,
    # that do not overlap.  The tricky bit here is processing policies in
    # order and accounting for denies.  We do this once for each
    # (from_zone, to_zone, app) tuple.  The other tricky bit is handling
    # the application "any", which we treat as including all applications
    # used anywhere, and also record in a special "@@other" app.
    permit_rules_by_app = {}
    rule_name_mapping = {}
    permit_deny_rules = {}

    all_apps = set(itertools.chain(*[p.applications for p in policies]))
    all_apps = all_apps | set(app_map.keys())
    all_apps.discard('any')
    if 'tcp_all' in all_apps:
        all_apps.discard('tcp_all')
        all_apps = all_apps | set(tcp_all)
    if 'udp_all' in all_apps:
        all_apps.discard('udp_all')
        all_apps = all_apps | set(udp_all)

    for app in all_apps:
        mapped_app = app_map[app]
        permit_deny_rules[mapped_app] = {"regular_policies": [], "global_policies": []}
        rule_name_mapping[mapped_app] = defaultdict(default_value)

    for zone_pairs, policies in policies_by_zone_pair.iteritems():
        for policy in policies:
            src = src_per_policy[policy]
            dst = dst_per_policy[policy]

            if 'any' in policy.applications:
                apps = all_apps
            else:
                apps = set(policy.applications)

            if 'tcp_all' in apps:
                apps.discard('tcp_all')
                apps = apps | set(tcp_all)

            if 'udp_all' in apps:
                apps.discard('udp_all')
                apps = apps | set(udp_all)

            if zone_pairs == (None, None):
                priority = "global_policies"
            else:
                priority = "regular_policies"

            for app in apps:
                permit_deny_rules[app_map[app]][priority].append(FWRuleSequence(src, dst, policy.applications,
                                                                                policy.name, policy.action,
                                                                                policy.sequence))
                rule_name_mapping[app_map[app]][policy.name].append(RuleNameMappingEntry(src, dst,
                                                                                         policy.sequence, priority,
                                                                                         policy.name))

    for app in all_apps:
        for priority in ["regular_policies", "global_policies"]:
            permit_deny_rules[app_map[app]][priority].sort(key=lambda r: r.sequence)

    global_policies = sorted(policies_by_zone_pair.get((None, None), []),
                             key=lambda p: p.sequence)

    for from_zone, to_zone in itertools.product(zone_nets, zone_nets):
        zpolicies = sorted(policies_by_zone_pair.get((from_zone, to_zone), []),
                           key=lambda p: p.sequence)
        zpolicies += global_policies
        logger.debug(" from-zone %s to-zone %s (%d policies)", from_zone, to_zone,
                     len(zpolicies))
        apps = set(itertools.chain(*[p.applications for p in zpolicies]))

        if 'any' in apps:
            apps = all_apps
        if 'tcp_all' in apps:
            apps.discard('tcp_all')
            apps = apps | set(tcp_all)
        if 'udp_all' in apps:
            apps.discard('udp_all')
            apps = apps | set(udp_all)

        logger.info("start parallel phase 1 for %s to %s", from_zone, to_zone)
        mapped_apps = [app_map[app] for app in apps]
        pairs = process_pool.map(process_permit_rules_by_app_star,
                                 content_generator(mapped_apps, from_zone, to_zone, zone_nets, zpolicies,
                                                   src_per_policy,
                                                   dst_per_policy))
        for mapped_app, permit_rules in pairs:
            permit_rules_app = permit_rules_by_app.setdefault(mapped_app, [])
            permit_rules_app += permit_rules
        logger.info("end parallel phase 1")
        logger.debug(" from-zone %s to-zone %s finished", from_zone, to_zone)

    permit_rules_by_app = simplify_rules(permit_rules_by_app)

    logger.info("start parallel phase 2")
    process_pool.map(write_app_to_file_star,
                     file_content_generator(apps_dir, all_apps, app_map, permit_rules_by_app, rule_name_mapping,
                                            permit_deny_rules))
    logger.info("end parallel phase 2")

    # simplify and return the result
    return all_apps


def close_and_join_process_pool():
    process_pool.close()
    process_pool.join()

process_pool = Pool()
