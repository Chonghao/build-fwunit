from fwunit.ip import IP, IPSet
from logging import getLogger
import json

log = getLogger(__name__)

DEFAULT_ZONES_DICT = {
    "trust": {
        "address-sets": [],
        "addresses": [],
        "interfaces": ["reth1"]
    },
    "untrust": {
        "address-sets": [],
        "addresses": [],
        "interfaces": ["reth0"]
    }
}

DEFAULT_ROUTES_DICT = {
    "routing_table": [
        {
            "destination": "10.0.0.0/8",
            "interface": "reth1",
            "is_local": "False",
            "reject": "False"
        },
        {
            "destination": "0.0.0.0/0",
            "interface": "reth0",
            "is_local": "False",
            "reject": "False"
        }
    ]
}


def construct_default_zones():
    return parse_zones_from_json(DEFAULT_ZONES_DICT)


def construct_default_routes():
    return parse_routes_from_json(DEFAULT_ROUTES_DICT)


def get_as_list(elem):
    if type(elem) is list:
        return elem
    else:
        return [elem]


class Policy(object):

    def __init__(self, from_zone, to_zone, policy_dict):
        #: policy name
        self.name = policy_dict["name"]

        #: source zone name for this policy, or None for the global policy
        self.from_zone = from_zone

        #: destination zone name for this policy
        self.to_zone = to_zone

        #: boolean, true if the policy is enabled
        self.enabled = True

        #: policy sequence number
        self.sequence = int(policy_dict["sequence"])

        #: source addresses (by name) for the policy
        self.source_addresses = get_as_list(policy_dict["src"])

        #: destination addresses (by name) for the policy
        self.destination_addresses = get_as_list(policy_dict["dst"])

        #: applications (name) for the policy
        self.applications = get_as_list(policy_dict["app"])

        #: 'permit' or 'deny'
        self.action = policy_dict["action"]

    def __str__(self):
        return ("%(action)s %(from_zone)s:%(source_addresses)r -> "
                "%(to_zone)s:%(destination_addresses)r : %(applications)s") % self.__dict__


class Route(object):

    """A route from the firewall's routing table"""

    def __init__(self, rt_entry):
        #: IPSet based on the route destination
        self.destination = IP(rt_entry["destination"])

        #: interface to which traffic is forwarded (via or local)
        self.interface = rt_entry["interface"]

        #: true if this destination is local (no next-hop IP)
        if rt_entry["is_local"] == "True":
            self.is_local = True
        else:
            self.is_local = False

        #: true if this is a "Reject" (blackhole) route
        if rt_entry["reject"] == "True":
            self.reject = True
        else:
            self.reject = False

    def __str__(self):
        return "%s via %s" % (self.destination, self.interface)

_default_addresses = {
    'any': IPSet([IP('0.0.0.0/0')]),
    'any-ipv4': IPSet([IP('0.0.0.0/0')]),
    # fwunit doesn't handle ipv6, so this is an empty set
    'any-ipv6': IPSet([]),
}


class Zone(object):

    """Parse out zone names and the corresponding interfaces"""

    def __init__(self, zone_name, zone_info):
        #: name
        self.name = zone_name

        #: list of interface names
        self.interfaces = zone_info["interfaces"]

        #: name -> ipset, based on the zone's address book
        self.addresses = _default_addresses.copy()
        for prefix_dict in zone_info["addresses"]:
            self.addresses[prefix_dict["name"]] = IPSet([IP(prefix_dict["prefix"])])
        for addr_set_name, addr_set_list in zone_info["address-sets"]:
            ip = IPSet()
            for set_name in addr_set_list:
                ip += self.addresses[set_name]
            self.addresses[addr_set_name] = ip

    def __str__(self):
        return "%s on %s" % (self.name, self.interfaces)


def get_as_IPSet(str_list):
    _ret = IPSet()
    for ip_str in str_list:
        _ret += IPSet([IP(ip_str)])
    return _ret


class AddressBook(object):
    """Parse named address books"""
    def __init__(self, zone_name, zone_addr_book):
        self.name = zone_name
        #: list of zone names
        self.attaches = zone_addr_book["attach"]

        #: name -> ipset, based on the zone's address book
        self.addresses = _default_addresses.copy()
        for prefix_pair in zone_addr_book["addresses"]:
            self.addresses[prefix_pair["name"]] = get_as_IPSet(prefix_pair["prefix"])

    def __str__(self):
        return self.name


class Firewall(object):

    def __init__(self, policies_path, address_books_path, zones_path=None, routes_path=None):

        #: list of security zones
        if zones_path:
            with open(zones_path, 'r') as f:
                self.zones = parse_zones_from_json(json.load(f))
        else:
            self.zones = construct_default_zones()

        #: list of Policy instances
        with open(policies_path, 'r') as f:
            self.policies = parse_policies_from_json(json.load(f))

        #: list of Route instances from 'inet.0'
        if routes_path:
            with open(routes_path, 'r') as f:
                self.routes = parse_routes_from_json(json.load(f))
        else:
            self.routes = construct_default_routes()

        #: list of AddressBook instances
        with open(address_books_path, 'r') as f:
            self.address_books = parse_address_books_from_json(json.load(f))


def parse_zones_from_json(zone_dict):
    zones = []
    for zone_name, zone_info in zone_dict.iteritems():
        zones.append(Zone(zone_name, zone_info))
    return zones


def parse_policies_from_json(policies_dict):
    policies = []
    for zone_pair, zone_pair_policies in policies_dict.iteritems():
        if zone_pair == 'global':
            from_zone = None
            to_zone = None
        else:
            from_zone, to_zone = zone_pair.split()
        for zone_pair_policy in zone_pair_policies:
            policies.append(Policy(from_zone, to_zone, zone_pair_policy))
    return policies


def parse_routes_from_json(routes_dict):
    routes = []
    for rt_entry in routes_dict["routing_table"]:
        routes.append(Route(rt_entry))
    return routes


def parse_address_books_from_json(address_books_dict):
    address_books = []
    for zone_name, zone_addr_book in address_books_dict.iteritems():
        address_books.append(AddressBook(zone_name, zone_addr_book))
    return address_books
