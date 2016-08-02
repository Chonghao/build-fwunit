import os
import json
import pickle

from nose.tools import eq_
from fwunit.ip import IP, IPSet
from fwunit.json import scripts
import fwunit.diff_json as diff
import fwunit.json.process as process
from fwunit.test.util.path_util import ensure_dir

cur_dir = os.path.dirname(__file__)
data_dir = os.path.abspath(os.path.join(cur_dir, '../data/gen_diff'))

gen_diff_diff1_expect = {'allowed_access_flows': {('rule 1', 'rule 1'): [
    ['tcp-80', IPSet([IP('0.0.0.0/1')]), IPSet([IP('128.0.0.0/1')])]]}, 'blocked_access_flows': {}}

gen_diff_diff2_expect = {'allowed_access_flows': {}, 'blocked_access_flows': {
    ('rule 1', 'rule 2'): [['tcp-80', IPSet([IP('0.0.0.0/0')]), IPSet([IP('96.0.0.0/3'), IP('128.0.0.0/3')])]]}}

gen_diff_diff3_expect = {'allowed_access_flows': {('rule 1', 'rule 3'): [
    ['tcp-80', IPSet([IP('0.0.0.0/0')]), IPSet([IP('192.0.0.0/2')])]]}, 'blocked_access_flows': {
    ('rule 2', 'rule 2'): [['tcp-80', IPSet([IP('0.0.0.0/0')]), IPSet([IP('96.0.0.0/3')])]]}}


def process_modified_flow(app_info):
    _ret = {
        'app': app_info[0],
        'src': str(app_info[1]),
        'dst': str(app_info[2])
    }
    return _ret


def massage_to_jsonable(diff_pic):
    _ret = {}
    for flow_type in ['allowed_access_flows', 'blocked_access_flows']:
        flow_info = {}
        for rule_pair, flow_by_app in diff_pic[flow_type].iteritems():
            flow_info[str(rule_pair)] = []
            for app_info in flow_by_app:
                flow_info[str(rule_pair)].append(process_modified_flow(app_info))
        _ret[flow_type] = flow_info
    return _ret


def load_pickle(pickle_path):
    with open(pickle_path, 'r') as f:
        return pickle.load(f)


def get_apps_dict(all_apps, apps_dir):
    _ret = {}
    for app_name in all_apps:
        app_path = os.path.join(apps_dir, app_name)
        app_dict = load_pickle(app_path)
        for k, v in app_dict.iteritems():
            _ret[k] = v
    return _ret


def test_diff1():
    test_dir = os.path.join(data_dir, 'diff_test1')

    old_policy_dir = os.path.join(test_dir, 'old_policy')
    old_globals_path = os.path.join(old_policy_dir, 'old_prefix.json')
    old_rules_path = os.path.join(old_policy_dir, 'old_rules.json')
    old_apps_dir = os.path.join(old_policy_dir, 'apps')
    ensure_dir(old_apps_dir)

    new_policy_dir = os.path.join(test_dir, 'new_policy')
    new_globals_path = os.path.join(new_policy_dir, 'new_prefix.json')
    new_rules_path = os.path.join(new_policy_dir, 'new_rules.json')
    new_apps_dir = os.path.join(new_policy_dir, 'apps')
    ensure_dir(new_apps_dir)

    diff_path_pickle = os.path.join(test_dir, 'diff/diff1.pickle')
    diff_path_json = os.path.join(test_dir, 'diff/diff1.json')

    all_apps_old = scripts.run(old_rules_path, old_globals_path, old_apps_dir)
    all_apps_new = scripts.run(new_rules_path, new_globals_path, new_apps_dir)

    policy_diff = diff.make_diff(old_apps_dir, new_apps_dir)
    with open(diff_path_pickle, 'wb') as f:
        pickle.dump(policy_diff, f)

    policy_jsonable = massage_to_jsonable(policy_diff)
    with open(diff_path_json, 'wb') as f:
        json.dump(policy_jsonable, f, indent=4)

    eq_(gen_diff_diff1_expect, policy_diff)


def test_diff2():
    test_dir = os.path.join(data_dir, 'diff_test2')

    old_policy_dir = os.path.join(test_dir, 'old_policy')
    old_globals_path = os.path.join(old_policy_dir, 'old_prefix.json')
    old_rules_path = os.path.join(old_policy_dir, 'old_rules.json')
    old_apps_dir = os.path.join(old_policy_dir, 'apps')
    ensure_dir(old_apps_dir)

    new_policy_dir = os.path.join(test_dir, 'new_policy')
    new_globals_path = os.path.join(new_policy_dir, 'new_prefix.json')
    new_rules_path = os.path.join(new_policy_dir, 'new_rules.json')
    new_apps_dir = os.path.join(new_policy_dir, 'apps')
    ensure_dir(new_apps_dir)

    diff_path_pickle = os.path.join(test_dir, 'diff/diff2.pickle')
    diff_path_json = os.path.join(test_dir, 'diff/diff2.json')

    all_apps_old = scripts.run(old_rules_path, old_globals_path, old_apps_dir)
    all_apps_new = scripts.run(new_rules_path, new_globals_path, new_apps_dir)

    policy_diff = diff.make_diff(old_apps_dir, new_apps_dir)
    with open(diff_path_pickle, 'wb') as f:
        pickle.dump(policy_diff, f)

    policy_jsonable = massage_to_jsonable(policy_diff)
    with open(diff_path_json, 'wb') as f:
        json.dump(policy_jsonable, f, indent=4)

    eq_(gen_diff_diff2_expect, policy_diff)


def test_diff3():
    test_dir = os.path.join(data_dir, 'diff_test3')

    old_policy_dir = os.path.join(test_dir, 'old_policy')
    old_globals_path = os.path.join(old_policy_dir, 'old_prefix.json')
    old_rules_path = os.path.join(old_policy_dir, 'old_rules.json')
    old_apps_dir = os.path.join(old_policy_dir, 'apps')
    ensure_dir(old_apps_dir)

    new_policy_dir = os.path.join(test_dir, 'new_policy')
    new_globals_path = os.path.join(new_policy_dir, 'new_prefix.json')
    new_rules_path = os.path.join(new_policy_dir, 'new_rules.json')
    new_apps_dir = os.path.join(new_policy_dir, 'apps')
    ensure_dir(new_apps_dir)

    diff_path_pickle = os.path.join(test_dir, 'diff/diff3.pickle')
    diff_path_json = os.path.join(test_dir, 'diff/diff3.json')

    all_apps_old = scripts.run(old_rules_path, old_globals_path, old_apps_dir)
    all_apps_new = scripts.run(new_rules_path, new_globals_path, new_apps_dir)

    policy_diff = diff.make_diff(old_apps_dir, new_apps_dir)
    with open(diff_path_pickle, 'wb') as f:
        pickle.dump(policy_diff, f)

    policy_jsonable = massage_to_jsonable(policy_diff)
    with open(diff_path_json, 'wb') as f:
        json.dump(policy_jsonable, f, indent=4)

    eq_(gen_diff_diff3_expect, policy_diff)


# def test_close_pools():
#     process.close_and_join_process_pool()
#     diff.close_and_join_diff_pool()
