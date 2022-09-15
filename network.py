#!/usr/bin/python3

# Copyright (C) 2022  Miroslav Lichvar <mlichvar@redhat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import argparse
import logging
import select
import sys
import time

import ntpnode

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test NTPv5 nodes in simulated network.")
    parser.add_argument("primary_nodes", help="number of stratum=1 nodes", type=int)
    parser.add_argument("secondary_nodes", help="number of stratum>1 nodes", type=int)
    parser.add_argument("topology", help="network topology of stratum>1 nodes (chain, uniring, biring, mesh)")
    parser.add_argument("-p", "--first-port", dest="first_port", metavar="PORT", type=int,
                        default=10123, help="specify port of first node (default 10123)")
    parser.add_argument("-v", "--version", dest="version", metavar="VERSION", type=int,
                        default=0, help="specify client NTP version (default negotiation)")
    parser.add_argument("-i", "--poll", dest="poll", type=int,
                        default=0, help="specify polling interval in log2 seconds (default 0)")
    parser.add_argument("-f", "--refids-fragments", dest="refids_fragments", metavar="NUMBER", type=int,
                        default=4, help="specify number of Bloom filter fragments (default 4)")
    parser.add_argument("-r", "--dispersion-rate", dest="dispersion_rate", metavar="RATE", type=float,
                        default=5e-3, help="specify dispersion rate (default 5e-3)")
    parser.add_argument("-m", "--max-distance", dest="max_distance", metavar="DIST", type=float,
                        default=1e-1, help="specify dispersion rate (default 1e-1)")
    parser.add_argument("-d", "--debug", dest="debug", action="count",
                        default=0, help="increase debug level")

    args = parser.parse_args()

    logging.basicConfig(format="%(message)s")
    logging.getLogger().setLevel([logging.WARN, logging.INFO, logging.DEBUG][args.debug])

    nodes = []

    print("Network:")

    for i in range(args.primary_nodes):
        nodes.append(ntpnode.NtpNode(True, args.first_port + i, args.max_distance, args.dispersion_rate,
                                     False, [], args.version, args.poll, False, args.refids_fragments))
        print("  {}".format(i))

    for i in range(args.secondary_nodes):
        servers=[]
        ids=[]
        for j in range(args.secondary_nodes):
            if args.topology == "chain":
                if i - 1 != j:
                    continue
            elif args.topology == "uniring":
                if i not in (j + 1, j - args.secondary_nodes + 1):
                    continue
            elif args.topology == "biring":
                if i not in (j - 1, j + 1, j - args.secondary_nodes + 1, j + args.secondary_nodes - 1):
                    continue
            elif args.topology == "mesh":
                if i == j:
                    continue
            else:
                logging.error("Unknown topology")
                sys.exit(1)
            servers.append("127.0.0.1:{}".format(args.first_port + args.primary_nodes + j))
            ids.append(args.primary_nodes + j)
        if i < args.primary_nodes:
            servers.append("127.0.0.1:{}".format(args.first_port + i))
            ids.append(i)

        print("  {} <- {}".format(args.primary_nodes + i, ids))

        nodes.append(ntpnode.NtpNode(False, args.first_port + args.primary_nodes + i, args.max_distance,
                                     args.dispersion_rate,
                                     False, servers, args.version, args.poll, False, args.refids_fragments))

    start_time = time.monotonic()
    while True:
        descriptors = []
        timeout = 1e10
        for node in nodes:
            timeout = min(timeout, node.get_timeout())
            descriptors += node.get_descriptors()

        rlist, _, _ = select.select(descriptors, [], [], timeout)

        for node in nodes:
            node.process_events(wait=False)

        if not rlist:
            print("Selection at {:.1f}:".format(time.monotonic() - start_time))

            sels = []
            for i, node in enumerate(nodes):
                ids = [s[1] - args.first_port for s in node.selected_sources]
                sels.append(set(ids))
                print("  {} <- {}".format(i, ids))

            looped = []
            for i in range(len(nodes)):
                visited = sels[i]
                while True:
                    prev_len = len(visited)
                    for j in list(visited):
                        visited |= sels[j]
                    if i in visited:
                        looped.append(i)
                        break
                    if prev_len == len(visited):
                        break

            print("Looped nodes: {}".format(looped))
