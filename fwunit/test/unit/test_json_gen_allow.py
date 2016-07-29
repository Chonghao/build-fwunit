import os
import pickle

from nose.tools import eq_
from fwunit.ip import IP, IPSet
from fwunit.types import RuleNameMappingEntry, FWRuleSequence, Rule
from fwunit.json import scripts
import fwunit.json.process as process

cur_dir = os.path.dirname(__file__)
data_dir = os.path.abspath(os.path.join(cur_dir, '../data/gen_allow'))

gen_allow_simple1_expect = {
    'tcp-80': [
        [Rule(src=IPSet(
            [IP('172.16.0.0/24'), IP('172.16.2.0/23'), IP('172.16.4.0/22'), IP('172.16.8.0/21'), IP('172.16.16.0/20'),
             IP('172.16.32.0/19'), IP('172.16.64.0/18'), IP('172.16.128.0/17')]), dst=IPSet([IP('0.0.0.0/0')]),
            app='tcp-80', name='rule 2')],
        {'rule 1': [RuleNameMappingEntry(src=IPSet([IP('172.16.1.0/24')]), dst=IPSet([IP('0.0.0.0/0')]), sequence=1,
                                         priority='global_policies', name='rule 1')], 'rule 2': [
            RuleNameMappingEntry(src=IPSet([IP('172.16.0.0/16')]), dst=IPSet([IP('0.0.0.0/0')]), sequence=2,
                                 priority='global_policies', name='rule 2')]},
        {'regular_policies': [], 'global_policies': [
            FWRuleSequence(src=IPSet([IP('172.16.1.0/24')]), dst=IPSet([IP('0.0.0.0/0')]), app=['tcp-80'],
                           name='rule 1', permission='deny', sequence=1),
            FWRuleSequence(src=IPSet([IP('172.16.0.0/16')]), dst=IPSet([IP('0.0.0.0/0')]), app=['tcp-80'],
                           name='rule 2', permission='permit', sequence=2)]}
    ]
}

gen_allow_simple2_expect = {
    'tcp-8080': [
        [Rule(src=IPSet([IP('10.0.0.0/8')]), dst=IPSet([IP('0.0.0.0/0')]), app='tcp-8080', name='rule 2'),
         Rule(src=IPSet(
             [IP('0.0.0.0/5'), IP('8.0.0.0/7'), IP('11.0.0.0/8'), IP('12.0.0.0/6'), IP('16.0.0.0/4'), IP('32.0.0.0/3'),
              IP('64.0.0.0/2'), IP('128.0.0.0/1')]), dst=IPSet([IP('0.0.0.0/2'), IP('96.0.0.0/3'), IP('128.0.0.0/1')]),
             app='tcp-8080', name='rule 2'),
         Rule(src=IPSet(
             [IP('0.0.0.0/5'), IP('8.0.0.0/7'), IP('11.0.0.0/8'), IP('12.0.0.0/6'), IP('16.0.0.0/4'), IP('32.0.0.0/3'),
              IP('64.0.0.0/3'), IP('128.0.0.0/1')]), dst=IPSet([IP('64.0.0.0/3')]), app='tcp-8080', name='rule 2')],
        {
            'rule 1': [
                RuleNameMappingEntry(src=IPSet([IP('96.0.0.0/3')]), dst=IPSet([IP('64.0.0.0/3')]), sequence=1,
                                     priority='global_policies', name='rule 1')],
            'rule 2': [
                RuleNameMappingEntry(src=IPSet([IP('0.0.0.0/0')]), dst=IPSet([IP('0.0.0.0/0')]), sequence=2,
                                     priority='global_policies', name='rule 2')]
        },
        {'regular_policies': [],
         'global_policies': [
             FWRuleSequence(src=IPSet([IP('96.0.0.0/3')]), dst=IPSet([IP('64.0.0.0/3')]), app=['tcp-8080'],
                            name='rule 1', permission='deny', sequence=1),
             FWRuleSequence(src=IPSet([IP('0.0.0.0/0')]), dst=IPSet([IP('0.0.0.0/0')]), app=['tcp-8080'],
                            name='rule 2', permission='permit', sequence=2)]}
    ]
}

gen_allow_simple3_expect = {
    'tcp-5000': [
        [Rule(src=IPSet([IP('96.0.0.0/3'), IP('128.0.0.0/2'), IP('192.0.0.0/3')]),
              dst=IPSet([IP('64.0.0.0/3'), IP('192.0.0.0/3')]), app='tcp-5000',
              name='rule 2'),
         Rule(src=IPSet([IP('160.0.0.0/3'), IP('192.0.0.0/3')]),
              dst=IPSet([IP('96.0.0.0/3'), IP('128.0.0.0/2')]), app='tcp-5000',
              name='rule 2'),
         Rule(src=IPSet([IP('64.0.0.0/2')]), dst=IPSet([IP('128.0.0.0/3')]),
              app='tcp-5000', name='rule 1')],
        {
            'rule 1': [
                RuleNameMappingEntry(src=IPSet([IP('64.0.0.0/2')]),
                                     dst=IPSet([IP('128.0.0.0/3')]), sequence=1,
                                     priority='global_policies', name='rule 1')],
            'rule 2': [
                RuleNameMappingEntry(
                    src=IPSet([IP('32.0.0.0/3'), IP('64.0.0.0/2'), IP('128.0.0.0/3')]),
                    dst=IPSet([IP('96.0.0.0/3'), IP('128.0.0.0/2')]), sequence=2,
                    priority='global_policies',
                    name='rule 2'),
                RuleNameMappingEntry(src=IPSet(
                    [IP('96.0.0.0/3'), IP('128.0.0.0/2'), IP('192.0.0.0/3')]),
                    dst=IPSet([IP('64.0.0.0/2'), IP('128.0.0.0/2'),
                               IP('192.0.0.0/3')]), sequence=2,
                    priority='global_policies', name='rule 2')]},
        {'regular_policies': [],
         'global_policies': [
             FWRuleSequence(src=IPSet([IP('64.0.0.0/2')]), dst=IPSet([IP('128.0.0.0/3')]), app=['tcp-5000'],
                            name='rule 1', permission='permit', sequence=1),
             FWRuleSequence(src=IPSet([IP('32.0.0.0/3'), IP('64.0.0.0/2'), IP('128.0.0.0/3')]),
                            dst=IPSet([IP('96.0.0.0/3'), IP('128.0.0.0/2')]), app=['tcp-5000'], name='rule 2',
                            permission='deny', sequence=2),
             FWRuleSequence(src=IPSet([IP('96.0.0.0/3'), IP('128.0.0.0/2'), IP('192.0.0.0/3')]),
                            dst=IPSet([IP('64.0.0.0/2'), IP('128.0.0.0/2'), IP('192.0.0.0/3')]), app=['tcp-5000'],
                            name='rule 2', permission='permit', sequence=2)]}]}


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


def test_json_gen_allow_simple1():
    test_dir = os.path.join(data_dir, 'gen_allow_simple1')
    policies_path = os.path.join(test_dir, 'gen_allow_simple1-rules.json')
    globals_path = os.path.join(test_dir, 'gen_allow_simple1-prefix.json')
    apps_dir = os.path.join(test_dir, 'apps')
    all_apps = scripts.run(policies_path, globals_path, apps_dir)

    my_result = get_apps_dict(all_apps, apps_dir)

    eq_(gen_allow_simple1_expect, my_result)


def test_json_gen_allow_simple2():
    test_dir = os.path.join(data_dir, 'gen_allow_simple2')
    policies_path = os.path.join(test_dir, 'gen_allow_simple2-rules.json')
    globals_path = os.path.join(test_dir, 'gen_allow_simple2-prefix.json')
    apps_dir = os.path.join(test_dir, 'apps')
    all_apps = scripts.run(policies_path, globals_path, apps_dir)

    my_result = get_apps_dict(all_apps, apps_dir)

    eq_(gen_allow_simple2_expect, my_result)


def test_json_gen_allow_simple3():
    test_dir = os.path.join(data_dir, 'gen_allow_simple3')
    policies_path = os.path.join(test_dir, 'gen_allow_simple3-rules.json')
    globals_path = os.path.join(test_dir, 'gen_allow_simple3-prefix.json')
    apps_dir = os.path.join(test_dir, 'apps')
    all_apps = scripts.run(policies_path, globals_path, apps_dir)

    my_result = get_apps_dict(all_apps, apps_dir)

    eq_(gen_allow_simple3_expect, my_result)


def test_close_pools():
    process.close_and_join_process_pool()
