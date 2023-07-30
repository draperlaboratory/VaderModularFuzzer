# This file is derived from ktest-tool in KLEE
# ==============================================================================
# KLEE Release License
# ==============================================================================
# University of Illinois/NCSA
# Open Source License

# http://klee.github.io/

# Developed by:
#     KLEE Team
#     Stanford Checking Group

# Copyright (c) 2007-2009 Stanford University.
# All rights reserved.


# Maintained since 2009 by:
#     Software Reliability Group
#     http://srg.doc.ic.ac.uk/
#     Imperial College London


# Improved and extended since 2009 by many developers.  For a full list
# of contributors, refer to
#          https://github.com/klee/klee/graphs/contributors
# and the Git commit history.


# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal with
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:

#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimers.

#     * Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimers in the
#       documentation and/or other materials provided with the distribution.

#     * Neither the names of the KLEE Team, Stanford University,
#       Imperial College London, nor the names of its contributors may
#       be used to endorse or promote products derived from this
#       Software without specific prior written permission.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE
# SOFTWARE.

import os
import struct
import sys

version_no = 3


class KTestError(Exception):
    pass


class KTest:
    @staticmethod
    def fromfile(path):
        if not os.path.exists(path):
            print("ERROR: file %s not found" % (path))
            sys.exit(1)

        f = open(path, 'rb')
        hdr = f.read(5)
        if len(hdr) != 5 or (hdr != b'KTEST' and hdr != b"BOUT\n"):
            raise KTestError('unrecognized file')
        version, = struct.unpack('>i', f.read(4))
        if version > version_no:
            raise KTestError('unrecognized version')
        numArgs, = struct.unpack('>i', f.read(4))
        args = []
        for i in range(numArgs):
            size, = struct.unpack('>i', f.read(4))
            args.append(str(f.read(size).decode(encoding='ascii')))

        if version >= 2:
            symArgvs, = struct.unpack('>i', f.read(4))
            symArgvLen, = struct.unpack('>i', f.read(4))
        else:
            symArgvs = 0
            symArgvLen = 0

        numObjects, = struct.unpack('>i', f.read(4))
        objects = []
        for i in range(numObjects):
            size, = struct.unpack('>i', f.read(4))
            name = f.read(size)
            size, = struct.unpack('>i', f.read(4))
            bytes = f.read(size)
            objects.append((name, bytes))

        # Create an instance
        b = KTest(version, args, symArgvs, symArgvLen, objects)
        # Augment with extra filename field
        b.filename = path
        return b

    def __init__(self, version, args, symArgvs, symArgvLen, objects):
        self.version = version
        self.symArgvs = symArgvs
        self.symArgvLen = symArgvLen
        self.args = args
        self.objects = objects

        # add a field that represents the name of the program used to
        # generate this .ktest file:
        program_full_path = self.args[0]
        program_name = os.path.basename(program_full_path)
        # sometimes program names end in .bc, so strip them
        if program_name.endswith('.bc'):
            program_name = program_name[:-3]
        self.programName = program_name
