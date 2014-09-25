#!/usr/bin/env python

# A tool to enumerate CVEs to check based on the WordPress version.
# Copyright (c) 2014, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
A tool to enumerate CVEs to check based on the WordPress version.
By Mario Vilas (https://github.com/MarioVilas).
"""

import argparse
import os.path
import sqlite3
import sys

parser = argparse.ArgumentParser(
    description=("A tool to enumerate CVEs to check"
                 " based on the WordPress version.")
)
parser.add_argument("version", metavar="VERSION",
                    help="WordPress version number")
args = parser.parse_args()

wp_version = args.version.split(".")
assert len(wp_version) < 4, "Invalid version number"
wp_version = map(int, wp_version)
wp_version.extend([0, 0, 0, 0])
wp_version = tuple(wp_version[:4])
wp_major = (wp_version[0], 0, 0, 0)

db = os.path.join(os.path.dirname(__file__), "cve_wordpress.db")
conn = sqlite3.connect(db)
try:
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT cve, version, operator"
            " FROM cve_wordpress"
            " ORDER BY cve DESC;"
        )
        for cve, version, operator in cursor.fetchall():
            version = map(int, version.split("."))
            version.extend([0, 0, 0, 0])
            version = tuple(version[:4])
            if operator == "<=":
                match = (version >= wp_major and wp_version <= version)
            elif operator == "<":
                match = (version >= wp_major and wp_version < version)
            elif operator == "==":
                match = (version == wp_version)
            else:
                assert False
            if match:
                cursor.execute(
                    "SELECT description"
                    " FROM cve_wordpress"
                    " WHERE cve = ?"
                    " LIMIT 1;",
                    (cve,)
                )
                description, = cursor.fetchone()
                print cve, description
    except:
        conn.rollback()
        raise
    else:
        conn.commit()
finally:
    conn.close()

