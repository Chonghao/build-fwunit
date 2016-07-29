# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import
import argparse
import logging
import sys
import textwrap
from fwunit import diff as diff_module
from fwunit.json import process
from fwunit.json import scripts
from fwunit import diff_json as diff_json_module
from fwunit import log
from fwunit import types
from fwunit.analysis import config
import pkg_resources
import json
import pickle
import prettyip

# always use prettyip to print IPSets
prettyip.patch_ipy()

logger = logging.getLogger(__name__)


def _setup(parser):
    args = parser.parse_args(sys.argv[1:])
    log.setup(args.verbose)
    cfg = config.load_config(args.config_file)
    return args, cfg


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


def main():
    description = textwrap.dedent("""Process security policies into fwunit rules""")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--config', '-c',
        help="YAML configuration file", dest='config_file', type=str, default='fwunit.yaml')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--boto-verbose', action='store_true',
                        help="Enable VERY verbose logging from boto (if in use)")
    parser.add_argument('sources', nargs='*', help="sources to generate (default: ALL)")

    args, cfg = _setup(parser)
    if not args.boto_verbose:
        logging.getLogger('boto').setLevel(logging.CRITICAL)

    requested_sources = args.sources
    if not requested_sources or requested_sources == ['ALL']:
        requested_sources = cfg.keys()
    for source in requested_sources:
        if source not in cfg:
            parser.error("no such source '{}'".format(source))

    entry_points = {ep.name: ep for ep in pkg_resources.iter_entry_points('fwunit.types')}

    # sort all of the sources in dependency order
    requirements = {}
    for source in cfg:
        requirements[source] = cfg[source].get('require', [])

    ordered_sources = []
    def require(source):
        if source in ordered_sources:
            return
        for req in requirements[source]:
            if req not in cfg:
                parser.error("unknown requirement '{}'".format(source))
            require(req)
        ordered_sources.append(source)
    for source in requirements.iterkeys():
        require(source)

    for source in ordered_sources:
        if source not in requested_sources:
            continue
        src_cfg = cfg[source]
        if 'type' not in src_cfg:
            parser.error("source '{}' has no type".format(source))
        typ = src_cfg['type']
        if typ not in entry_points:
            parser.error("source '{}' has undefined type {}".format(source, typ))
        ep = entry_points[typ].load()

        if 'output' not in src_cfg:
            parser.error("source '{}' has no output".format(source))
        output = src_cfg['output']

        logger.warning("running %s", source)
        rules = ep(src_cfg, cfg)
        logger.warning("writing resulting rules to %s", output)
        json.dump(dict(rules=types.to_jsonable(rules)),
                  open(output, "w"))


def query():
    description = textwrap.dedent("""Query fwunit rules""")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--config', '-c',
        help="YAML configuration file", dest='config_file', type=str, default='fwunit.yaml')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--quiet', action='store_true')
    subparsers = parser.add_subparsers(
            title='subcommands',
            help='Use <subcommand> --help for help')

    # import the query classes
    from .query import permitted
    permitted.PermittedQuery(subparsers)
    from .query import denied
    denied.DeniedQuery(subparsers)
    from .query import apps
    apps.AppsQuery(subparsers)

    args, cfg = _setup(parser)
    if not args.verbose:
        logging.getLogger('').setLevel(logging.CRITICAL)

    if not args._func:
        parser.error("No subcomand given")

    args._func(args, cfg)


def diff():
    description = textwrap.dedent("""Print differences between two rule sets (sources)""")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--config', '-c',
        help="YAML configuration file", dest='config_file', type=str, default='fwunit.yaml')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('left', help='left source')
    parser.add_argument('right', help='right source')

    args, cfg = _setup(parser)
    if not args.verbose:
        logging.getLogger('').setLevel(logging.CRITICAL)

    diff_module.show_diff(cfg, args.left, args.right)


def diff_json():
    description = textwrap.dedent("""Calculate differences between two rule sets (sources) and write to file""")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--old_policies_path', required=True)
    parser.add_argument('--old_prefix_path', required=True)
    parser.add_argument('--old_apps_dir', required=True)
    parser.add_argument('--new_policies_path', required=True)
    parser.add_argument('--new_prefix_path', required=True)
    parser.add_argument('--new_apps_dir', required=True)
    parser.add_argument('--output_path', required=True)

    args = parser.parse_args(sys.argv[1:])

    diff_path_pickle = args.output_path + '.pickle'
    diff_path_json = args.output_path + '.json'

    # all_apps_old = scripts.run(args.old_policies_path, args.old_prefix_path, args.old_apps_dir)
    # all_apps_new = scripts.run(args.new_policies_path, args.new_prefix_path, args.new_apps_dir)

    process.close_and_join_process_pool()

    policy_diff = diff_json_module.make_diff(args.old_apps_dir, args.new_apps_dir)
    policy_diff_jsonable = massage_to_jsonable(policy_diff)

    with open(diff_path_pickle, "wb") as f:
        pickle.dump(policy_diff, f)

    with open(diff_path_json, "wb") as f:
        json.dump(policy_diff_jsonable, f, indent=4)

    diff_json_module.close_and_join_diff_pool()
