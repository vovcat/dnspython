#!/usr/bin/env python3

from typing import cast

import dns.resolver
from dns.rdtypes.ANY.MX import MX

answers = dns.resolver.resolve("nominum.com", "MX")
for rdata in answers:
    mx_rdata = cast(MX, rdata)
    print("Host", rdata.exchange, "has preference", rdata.preference)