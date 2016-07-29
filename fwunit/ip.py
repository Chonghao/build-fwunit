# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import IPy
import bisect

# IPy's IP seems sufficient
IP = IPy.IP


def combine_names(name1, name2):
    """Combine rule names, keeping all source names but removing duplicates"""
    names = set(name1.split('+')) | set(name2.split('+'))
    # as a special case, ignore 'unmanaged-*' names, as they add no useful information
    names = [n for n in names if not n.startswith('unmanaged-')]
    return '+'.join(sorted(names))


class IPSet(IPy.IPSet):
    # IPy's IPSet needs some help

    def isdisjoint(self, other):
        left = iter(self.prefixes)
        right = iter(other.prefixes)
        try:
            l = left.next()
            r = right.next()
            while True:
                if l in r or r in l:
                    return False
                if l < r:
                    l = left.next()
                else:
                    r = right.next()
        except StopIteration:
            return True

    def __and__(self, other):
        left = iter(self.prefixes)
        right = iter(other.prefixes)
        result = []
        try:
            l = left.next()
            r = right.next()
            while True:
                if l in r:
                    result.append(l)
                    l = left.next()
                    continue
                elif r in l:
                    result.append(r)
                    r = right.next()
                    continue
                if l < r:
                    l = left.next()
                else:
                    r = right.next()
        except StopIteration:
            return IPSet(result)

    # see https://github.com/haypo/python-ipy/pull/25
    def __contains__(self, ip):
        valid_masks = self.prefixtable.keys()
        if isinstance(ip, IP):
            #Don't dig through more-specific ranges
            ip_mask = ip._prefixlen
            valid_masks = [x for x in valid_masks if x <= ip_mask]
        for mask in sorted(valid_masks):
            i = bisect.bisect(self.prefixtable[mask], ip)
            # Because of sorting order, a match can only occur in the prefix
            # that comes before the result of the search.
            if i and ip in self.prefixtable[mask][i - 1]:
                return True

    # override to create instances of the correct class
    def __add__(self, other):
        return IPSet(self.prefixes + other.prefixes)

    # override to create instances of the correct class
    def __sub__(self, other):
        new = IPSet(self.prefixes)
        for prefix in other:
            new.discard(prefix)
        return new

    def __eq__(self, other):
        return self.prefixes == other.prefixes

    def __lt__(self, other):
        return self.prefixes < other.prefixes


class IPPairsOrdered(object):
    """Representation of an ordered list of source-destination pairs,
    with the ability to do some basic arithmetic"""

    def __init__(self, version, *pairs):
        # pairs is [src, dst, permission]
        # print "version", version
        # print "pairs", pairs
        self._pairs = list(pairs)
        self.version = version
        self.src_bounds, self.dst_bounds = self._get_boundaries()
        self.allow_rules = self._get_allow_rules()

    def _get_boundaries(self):
        src_bounds = set()
        dst_bounds = set()
        for src_set, dst_set, permission in self._pairs:
            for src in src_set:
                start = src.net().int()
                end = src.broadcast().int()+1
                src_bounds.add(start)
                src_bounds.add(end)
            for dst in dst_set:
                start = dst.net().int()
                end = dst.broadcast().int()+1
                dst_bounds.add(start)
                dst_bounds.add(end)
        if self.version == 4:
            for bound in [IP('0.0.0.0').int(), IP('255.255.255.255').int()+1]:
                src_bounds.add(bound)
                dst_bounds.add(bound)
        else:
            for bound in [IP('::').int(), IP('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').int()+1]:
                src_bounds.add(bound)
                dst_bounds.add(bound)
        return sorted(list(src_bounds)), sorted(list(dst_bounds))

    def _check_permission(self, src_range, dst_range):
        for src_set, dst_set, permission in self._pairs:
            match = True
            for src_cidr in src_range:
                if src_cidr not in src_set:
                    match = False
                    break
            if not match:
                continue
            for dst_cidr in dst_range:
                if dst_cidr not in dst_set:
                    match = False
                    break
            if match:
                return permission
        return 'deny'

    def _get_allow_rules(self):
        allowed_flows = []
        for i in xrange(len(self.src_bounds)-1):
            src_range = IPSet(iprange_to_cidrs_custom(self.src_bounds[i], self.src_bounds[i+1]-1))
            for j in xrange(len(self.dst_bounds)-1):
                dst_range = IPSet(iprange_to_cidrs_custom(self.dst_bounds[j], self.dst_bounds[j+1]-1))
                if self._check_permission(src_range, dst_range) == 'allow':
                    allowed_flows.append([src_range, dst_range])
        return IPPairs(*allowed_flows)


class IPPairs(object):
    """Reasonably compact representation of a set of source-destination pairs,
    with the ability to do some basic arithmetic."""

    def __init__(self, *pairs):
        self._pairs = list(pairs)
        self._optimize()

    def get_pairs(self):
        return self._pairs

    def __iter__(self):
        return self._pairs.__iter__()

    def __eq__(self, other):
        # TODO: this can show equal IPPairs that have been constructed
        # differently as different.  It's good enough for tests.
        return self._pairs == other._pairs

    def __repr__(self):
        return 'IPPairs(*[\n%s\n])' % ('\n'.join("  " + 
           '%r\n   -> %r' % p for p in self._pairs))

    def __add__(self, other):
        return IPPairs(*(self._pairs + other.get_pairs()))

    def __sub__(self, other):
        new_pairs = []
        empty = lambda pair: len(pair[0]) == 0 or len(pair[1]) == 0
        # the approach here is to successively break pairs in self down where they overlap
        # other, keeping only pairs that are completely disjoint with other.
        pairs_to_consider = self._pairs[:]
        while pairs_to_consider:
            sa, da = pairs_to_consider.pop(0)
            for sb, db in other._pairs:
                # eliminate non-overlap
                if sa.isdisjoint(sb) or da.isdisjoint(db):
                    continue
                for pair in (sa & sb, da - db), (sa - sb, da - db), (sa - sb, da & db):
                    if not empty(pair):
                        self.append = pairs_to_consider.append(pair)
                break
            else:
                # no pairs in `other` overlapped sa/da, so we can keep it
                new_pairs.append((sa, da))
        return IPPairs(*new_pairs)

    def __and__(self, other):
        new_pairs = []
        for sa, da in self._pairs:
            for sb, db in other._pairs:
                s = sa & sb
                d = da & db
                if len(s) and len(d):
                    new_pairs.append((s, d))
        return IPPairs(*new_pairs)


    def _optimize(self):
        if len(self._pairs) < 2:
            return
        while True:
            changed = False
            for reverse in 1, 0:  # finish with non-reversed
                self._pairs.sort(key=(lambda p: tuple(reversed(p)) if reverse else None))
                i = len(self._pairs) - 2
                while i >= 0:
                    if self._pairs[i][reverse] == self._pairs[i+1][reverse]:
                        if reverse:
                            self._pairs[i] = (self._pairs[i][0] + self._pairs[i+1][0], self._pairs[i][1])
                        else:
                            self._pairs[i] = (self._pairs[i][0], self._pairs[i][1] + self._pairs[i+1][1])
                        del self._pairs[i+1]
                        changed = True
                    i -= 1
            if not changed:
                break

    def __nonzero__(self):
        return len(self._pairs) != 0


class IPPairsRuleNum(object):
    """
    IPPairs with Rule Numbers attached
    """
    def __init__(self, *pairs):
        self._pairs = list(pairs)
        self._optimize()

    def __iter__(self):
        return self._pairs.__iter__()

    def __eq__(self, other):
        # TODO: this can show equal IPPairs that have been constructed
        # differently as different.  It's good enough for tests.
        return self._pairs == other._pairs

    def __repr__(self):
        return 'IPPairs(*[\n%s\n])' % ('\n'.join("  " +
           '%r\n   -> %r\n %r' % p for p in self._pairs))

    def __sub__(self, other):
        new_pairs = []
        empty = lambda pair: len(pair[0]) == 0 or len(pair[1]) == 0
        # the approach here is to successively break pairs in self down where they overlap
        # other, keeping only pairs that are completely disjoint with other.
        pairs_to_consider = self._pairs[:]
        while pairs_to_consider:
            sa, da, rule_num_a = pairs_to_consider.pop(0)
            for sb, db, rule_num_b in other._pairs:
                # eliminate non-overlap
                if sa.isdisjoint(sb) or da.isdisjoint(db):
                    continue
                for pair in (sa & sb, da - db, rule_num_a), (sa - sb, da - db, rule_num_a), (sa - sb, da & db, rule_num_a):
                    if not empty(pair):
                        pairs_to_consider.append(pair)
                break
            else:
                # no pairs in `other` overlapped sa/da, so we can keep it
                new_pairs.append((sa, da, rule_num_a))
        return IPPairsRuleNum(*new_pairs)

    def _optimize(self):
        if len(self._pairs) < 2:
            return
        while True:
            changed = False
            for reverse in 1, 0:  # finish with non-reversed
                self._pairs.sort(key=(lambda p: (p[1], p[0], p[2]) if reverse else None))
                i = len(self._pairs) - 2
                while i >= 0:
                    if self._pairs[i][reverse] == self._pairs[i+1][reverse]:
                        if reverse:
                            self._pairs[i] = (self._pairs[i][0] + self._pairs[i+1][0], self._pairs[i][1],
                                              combine_names(self._pairs[i][2], self._pairs[i+1][2]))
                        else:
                            self._pairs[i] = (self._pairs[i][0], self._pairs[i][1] + self._pairs[i+1][1],
                                              combine_names(self._pairs[i][2], self._pairs[i+1][2]))
                        del self._pairs[i+1]
                        changed = True
                    i -= 1
            if not changed:
                break

    def __nonzero__(self):
        return len(self._pairs) != 0


def increment_ip(ip, amt):
    return IP(ip.int() + amt)


def IP_int_prefixlen(ipnum, prefixlen, version):
    if version == 4:
        width = 32
    else:
        width = 128
    ipnum &= -(1 << (width - prefixlen))
    return IP("{0}/{1}".format(IPy.intToIp(ipnum, version), prefixlen))


def cidr_partition_custom(target, exclude):
    """
    Partitions a target IP subnet on an exclude IP address.

    Parameters
    ----------
    target: the target IP address or subnet to be divided up
    exclude: the IP address or subnet to partition on

    Returns
    -------
    list of 'IP' objects before, the partition, and after, sorted.
    Adding the three lists returns the equivalent of the original subnet.
    """
    target = IP(target)
    exclude = IP(exclude)

    if exclude.broadcast() < target.net():
        return [], [], [target]
    elif target.broadcast() < exclude.net():
        return [target], [], []

    if target.prefixlen() >= exclude.prefixlen():
        return [], [target], []

    left = []
    right = []

    new_prefixlen = target.prefixlen() + 1
    if exclude.version() == 4:
        version = 4
        target_module_width = 32
    else:
        version = 6
        target_module_width = 128
    target_first = target.net().int()

    i_lower = target_first
    i_upper = target_first + (2**(target_module_width - new_prefixlen))

    while exclude.prefixlen() >= new_prefixlen:
        if exclude.net().int() >= i_upper:
            left.append(IP_int_prefixlen(i_lower, new_prefixlen, version))
            matched = i_upper
        else:
            right.append(IP_int_prefixlen(i_upper, new_prefixlen, version))
            matched = i_lower

        new_prefixlen += 1

        if new_prefixlen > target_module_width:
            break

        i_lower = matched
        i_upper = matched + (2**(target_module_width - new_prefixlen))

    return left, [exclude], right[::-1]


def spanning_cidr_custom(ip_addrs):
    """
    Function that accepts a sequence of IP addresses and subnets returning a single 'IP' subnet that is large
    enough to span the lower and upper bound IP addresses with a possible overlap on either end

    Parameters
    ----------
    ip_addrs: sequence of IP addresses and subnets

    Returns
    -------
    a single spanning 'IP' subnet
    """
    sorted_ips = sorted(IP(ip) for ip in ip_addrs)
    lowest_ip = sorted_ips[0]
    highest_ip = sorted_ips[-1]
    ipnum = highest_ip.broadcast().int()
    prefixlen = highest_ip.prefixlen()
    lowest_ipnum = lowest_ip.net().int()
    if highest_ip.version() == 4:
        width = 32
    else:
        width = 128

    while prefixlen > 0 and ipnum > lowest_ipnum:
        prefixlen -= 1
        ipnum &= -(1 << (width-prefixlen))

    return IP_int_prefixlen(ipnum, prefixlen, highest_ip.version())


def iprange_to_cidrs_custom(start, end):
    """
    Function that accpets an arbitrary start and end IP address or subnet and returns a list of CIDR subnets that
    fit exactly between the boundaries of the two with no overlap.

    Parameters
    ----------
    start: the start IP address or subnet.
    end: the end IP address or subnet.

    Returns
    -------
    a list of one or more IP addresses and subnets
    """
    cidr_list = []

    start = IP(start)
    end = IP(end)

    iprange = [start.net().int(), end.broadcast().int()]

    # Get spanning CIDR covering both addresses.
    cidr_span = spanning_cidr_custom([start, end])
    if start.version() == 4:
        width = 32
    else:
        width = 128

    if cidr_span.net().int() < iprange[0]:
        exclude = IP_int_prefixlen(iprange[0]-1, width, start.version())
        cidr_list = cidr_partition_custom(cidr_span, exclude)[2]
        cidr_span = cidr_list.pop()
    if cidr_span.broadcast().int() > iprange[1]:
        exclude = IP_int_prefixlen(iprange[1]+1, width, start.version())
        cidr_list += cidr_partition_custom(cidr_span, exclude)[0]
    else:
        cidr_list.append(cidr_span)

    return cidr_list