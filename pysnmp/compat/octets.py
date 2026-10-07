#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
"""Octets helpers, local replacement for `pyasn1.compat.octets`.

`pyasn1.compat.octets` was removed in pyasn1 0.5.0. This module re-exports
it when an old pyasn1 still provides it, and otherwise implements the same
helpers locally (Python 3 semantics, matching pyasn1 0.4.x).
"""
try:
    from pysnmp.compat.octets import ints2octs  # noqa: F401
    from pysnmp.compat.octets import int2oct  # noqa: F401
    from pysnmp.compat.octets import null  # noqa: F401
    from pysnmp.compat.octets import oct2int  # noqa: F401
    from pysnmp.compat.octets import octs2ints  # noqa: F401
    from pysnmp.compat.octets import octs2str  # noqa: F401
    from pysnmp.compat.octets import str2octs  # noqa: F401
    from pysnmp.compat.octets import isStringType  # noqa: F401
    from pysnmp.compat.octets import isOctetsType  # noqa: F401
    from pysnmp.compat.octets import isIntsType  # noqa: F401
    from pysnmp.compat.octets import ensureString  # noqa: F401

except ImportError:
    # NOTE(keeper): pyasn1 >= 0.5 dropped pyasn1.compat.octets; the
    # definitions below mirror pyasn1 0.4.x Python 3 behaviour.
    ints2octs = bytes

    def int2oct(x):
        return ints2octs((x,))

    null = ints2octs()

    def oct2int(x):
        return x[0]

    def octs2ints(x):
        return list(x)

    def octs2str(x):
        return bytes(x).decode()

    def str2octs(x):
        return x.encode()

    def isStringType(x):
        return isinstance(x, str)

    def isOctetsType(x):
        return isinstance(x, bytes)

    def isIntsType(x):
        return isinstance(x, (tuple, list))

    def ensureString(x):
        return x.decode() if isinstance(x, bytes) else str(x)
