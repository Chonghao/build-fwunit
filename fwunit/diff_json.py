# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.ip import IPPairs
from fwunit.ip import IPPairsRuleNum
from fwunit.analysis import sources
from blessings import Terminal
from fwunit.types import ModifiedFlow
from collections import defaultdict
import itertools
from multiprocessing import Pool
import logging
import pickle
import os

terminal = Terminal()
log = logging.getLogger(__name__)

protocol_mapping = {
    6: 'tcp',
    17: 'udp'
}

protocol_reverse_mapping = {
    'tcp': 6,
    'udp': 17
}


def default_value():
    return []


def default_IPPairs():
    return IPPairs()


def break_down_flows(flow, left_mapping, right_mapping):
    src, dst, new_name, old_name = flow.src, flow.dst, flow.new_name, flow.old_name

    flow_by_old_rule = defaultdict(default_IPPairs)
    old_remaining_pairs = IPPairs((src, dst))

    old_rule_names = old_name.split('+')
    old_rules = list(itertools.chain(*[left_mapping[name] for name in old_rule_names]))
    old_globals = [rule for rule in old_rules if rule.priority == 'global_policies']
    old_regulars = [rule for rule in old_rules if rule.priority == 'regular_policies']
    all_old_rules = sorted(old_regulars, key=lambda r: r.sequence) + sorted(old_globals, key=lambda r: r.sequence)
    for rule in all_old_rules:
        old_src, old_dst = rule.src, rule.dst
        for s, d in old_remaining_pairs:
            s = s & old_src
            d = d & old_dst
            if len(s) and len(d):
                flow_by_old_rule[rule.name] += IPPairs((s, d))
        old_remaining_pairs -= IPPairs((old_src, old_dst))
        if not old_remaining_pairs:
            break

    flow_by_new_rule = defaultdict(default_IPPairs)
    new_remaining_pairs = IPPairs((src, dst))

    new_rule_names = new_name.split('+')
    new_rules = list(itertools.chain(*[right_mapping[name] for name in new_rule_names]))
    new_globals = [rule for rule in new_rules if rule.priority == 'global_policies']
    new_regulars = [rule for rule in new_rules if rule.priority == 'regular_policies']
    all_new_rules = sorted(new_regulars, key=lambda r: r.sequence) + sorted(new_globals, key=lambda r: r.sequence)
    for rule in all_new_rules:
        new_src, new_dst = rule.src, rule.dst
        for s, d in new_remaining_pairs:
            s = s & new_src
            d = d & new_dst
            if len(s) and len(d):
                flow_by_new_rule[rule.name] += IPPairs((s, d))
        new_remaining_pairs -= IPPairs((new_src, new_dst))
        if not new_remaining_pairs:
            break

    return flow_by_old_rule, flow_by_new_rule


def clean_names(modified_flows, left_rule_name_mapping, right_rule_name_mapping):
    _ret = []
    for modified_flow in modified_flows:
        flow_by_old_rule, flow_by_new_rule = break_down_flows(modified_flow, left_rule_name_mapping, right_rule_name_mapping)
        for new_rule, new_flows in flow_by_new_rule.iteritems():
            for old_rule, old_flows in flow_by_old_rule.iteritems():
                intersection = new_flows & old_flows
                for s, d in intersection.get_pairs():
                    _ret.append(ModifiedFlow(s, d, new_rule, old_rule))
    return _ret


def get_pairs(unordered_rules):
    return IPPairsRuleNum(*[(r.src, r.dst, r.name) for r in unordered_rules])


def app_diff(app_name, old_app_path, new_app_path):
    with open(old_app_path, 'r') as f:
        left_tuple = pickle.load(f)[app_name]
    with open(new_app_path, 'r') as f:
        right_tuple = pickle.load(f)[app_name]

    _ret = {'allowed_access_flows': defaultdict(default_value), 'blocked_access_flows': defaultdict(default_value)}
    left_permit_rules, left_rule_name_mapping, left_ordered_rules = left_tuple
    right_permit_rules, right_rule_name_mapping, right_ordered_rules = right_tuple

    right_permit_pairs = get_pairs(right_permit_rules)
    left_permit_pairs = get_pairs(left_permit_rules)

    added = right_permit_pairs - left_permit_pairs
    allowed_access_flows = []
    for pair in added:
        src, dst, name = pair
        remaining_pairs = IPPairs((src, dst))
        for old_rule in filter(lambda r: r.permission == 'deny', left_ordered_rules['regular_policies'] + left_ordered_rules['global_policies']):
            s_old, d_old, old_rule_name = old_rule.src, old_rule.dst, old_rule.name
            for s, d in remaining_pairs:
                s = s & s_old
                d = d & d_old
                if len(s) and len(d):
                    allowed_access_flows.append(ModifiedFlow(s, d, name, old_rule_name))
            remaining_pairs -= IPPairs((s_old, d_old))
            if not remaining_pairs:
                break
    cleaned_allowed_access_flows = clean_names(allowed_access_flows, left_rule_name_mapping, right_rule_name_mapping)

    removed = left_permit_pairs - right_permit_pairs
    blocked_access_flows = []
    for pair in removed:
        src, dst, name = pair
        remaining_pairs = IPPairs((src, dst))
        for new_rule in filter(lambda r: r.permission == 'deny', right_ordered_rules['regular_policies'] + right_ordered_rules['global_policies']):
            s_new, d_new, new_rule_name = new_rule.src, new_rule.dst, new_rule.name
            for s, d in remaining_pairs:
                s = s & s_new
                d = d & d_new
                if len(s) and len(d):
                    blocked_access_flows.append(ModifiedFlow(s, d, new_rule_name, name))
            remaining_pairs -= IPPairs((s_new, d_new))
            if not remaining_pairs:
                break
    cleaned_blocked_access_flows = clean_names(blocked_access_flows, left_rule_name_mapping, right_rule_name_mapping)

    for flow in cleaned_allowed_access_flows:
        _ret['allowed_access_flows'][(flow.new_name, flow.old_name)].append([app_name, flow.src, flow.dst])
    for flow in cleaned_blocked_access_flows:
        _ret['blocked_access_flows'][(flow.new_name, flow.old_name)].append([app_name, flow.src, flow.dst])

    return _ret


def app_diff_star(args):
    return app_diff(*args)


def app_path_generator(all_apps, old_apps_dir, new_apps_dir):
    for app in all_apps:
        yield (app, os.path.join(old_apps_dir, app), os.path.join(new_apps_dir, app))


def make_diff(old_apps_dir, new_apps_dir):
    _ret = {'allowed_access_flows': defaultdict(default_value), 'blocked_access_flows': defaultdict(default_value)}

    log.info("start parallel part")
    old_apps = os.listdir(old_apps_dir)
    new_apps = os.listdir(new_apps_dir)
    all_apps = sorted(set(old_apps) | set(new_apps))

    # # implementation 1:
    # #     first write apps to files in parallel
    # #     then read apps from files and process in parallel
    # # this implementation would make it easier to distribute the computation over many machines
    # log.info("start writing apps to files")
    # # phase 1: write apps to files
    # diff_pool.imap_unordered(write_app_to_file_star, file_content_generator(all_apps, dir_path, left, right))
    # log.info("end writing apps to files")
    # log.info("start processing individual apps")
    # phase 2: read in files and calculate diff
    for app_dict in diff_pool.imap_unordered(app_diff_star, app_path_generator(all_apps, old_apps_dir, new_apps_dir)):
        for c in ['allowed_access_flows', 'blocked_access_flows']:
            for k in app_dict[c].keys():
                _ret[c][k] += app_dict[c][k]
    log.info("end processing individual apps")
    log.info("start sorting part")
    for flow in _ret['allowed_access_flows'].values():
        flow.sort(key=lambda x: protocol_reverse_mapping[x[0].split('-')[0]]*65536 + int(x[0].split('-')[1]))
    for flow in _ret['blocked_access_flows'].values():
        flow.sort(key=lambda x: protocol_reverse_mapping[x[0].split('-')[0]]*65536 + int(x[0].split('-')[1]))
    log.info("end sorting part")

    return _ret


def close_and_join_diff_pool():
    diff_pool.close()
    diff_pool.join()

diff_pool = Pool()
