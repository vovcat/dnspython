# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from typing import Any, Dict, Iterable, Optional, Tuple, Union

import dns.immutable
import dns.rdata

@dns.immutable.immutable
class WR(dns.rdata.Rdata):
    """WR record"""

    __slots__ = ["strings"]

    def __init__(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        strings: Iterable[Union[bytes, str]],
    ):
        """Initialize a TXT-like rdata.
        *rdclass*, an ``int`` is the rdataclass of the Rdata.
        *rdtype*, an ``int`` is the rdatatype of the Rdata.
        *strings*, a tuple of ``bytes``
        """
        super().__init__(rdclass, rdtype)

        self.strings: Tuple[bytes] = self._as_tuple(
            strings, lambda x: self._as_bytes(x, True)
        )

    def to_text(
        self,
        origin: Optional[dns.name.Name] = None,
        relativize: bool = True,
        **kw: Dict[str, Any],
    ) -> str:
        txt = b''.join(self.strings)
        return txt.decode()

    @classmethod
    def from_text(
        cls,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        tok: dns.tokenizer.Tokenizer,
        origin: Optional[dns.name.Name] = None,
        relativize: bool = True,
        relativize_to: Optional[dns.name.Name] = None,
    ) -> dns.rdata.Rdata:
        t = tok.get()
        s = f'{t.value}'
        if t.is_quoted_string():
            # read closing quote mark
            s = f'{t.value} {tok.get().value}'
        while True:
            c = tok._get_char()
            if c == '\n': tok._unget_char(c); break
            if c == '': break
            s += c
        return cls(rdclass, rdtype, [s.encode()])

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None):
        strings = []
        while parser.remaining() > 0:
            s = parser.get_counted_bytes()
            strings.append(s)
        return cls(rdclass, rdtype, strings)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        for s in self.strings:
            with dns.renderer.prefixed_length(file, 2):
                file.write(s)
