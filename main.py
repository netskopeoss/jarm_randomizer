#!/usr/bin/env python3
"""
Copyright 2021 Netskope, Inc.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Written by Dagmawi Mulugeta
"""

import ssl
import random
import json
import time
import config
import proxy_handler

from http.server import HTTPServer
from threading import Thread


def get_jarm_from_local(tls_version, cipher):
    """ 
    Grab the JARM fingerprint from the local 'possible_jarms' store. 
    This should be ran after setup.sh to output the possible configurations.
    """
    try:
        with open(config.paths['possible_jarms']) as _file:
            jarms = json.load(_file)
        for j in jarms:
            if any(c['tls_version'] == tls_version and c['cipher'] == cipher for c in jarms[j]['configs']):
                return j
    except:
        return ''


def grab_valid_configs(return_all=False):
    """ 
    Grab all the valid configurations for this system
    """
    tls_version = config.force_ssl_version if config.force_ssl_version else None
    cipher = config.force_cipher if config.force_ssl_version else None
    if tls_version and cipher:
        return tls_version, cipher, get_jarm_from_local(tls_version, cipher)
    else:
        with open(config.paths['valid_configs']) as _file:
            valid_configs = json.load(_file)
        if return_all:
            new_valid_configs = list({e['jarm']: e for e in valid_configs}.values())
            return new_valid_configs
        else:
            choice = random.choice(valid_configs)
            return int(choice['tls_version']), choice['cipher'], choice['jarm']


def start_server(version, cipher, jarm):
    """ 
    Start the Proxy Server on the desired network and port. 
    """
    httpd = HTTPServer((config.ip, config.port), proxy_handler.ProxyHandler)
    httpd.socket = ssl.wrap_socket(
        sock=httpd.socket,
        keyfile=config.keyfile,
        certfile=config.certfile,
        server_side=True,
        ssl_version=version,
        ciphers=cipher
    )
    print(f"\n[x] Selected configs: TLS -> {version}, Cipher -> {cipher}, JARM -> {jarm}")
    if config.cycle_jarms:
        print(f"[x] Cycle mode selected: server running on https://{config.ip}:{config.port} for {config.cycle_interval_secs} secs")
        httpd.server_activate()
        thread = Thread(target=proxy_handler.serve_forever, args=(httpd,))
        thread.setDaemon(True)
        thread.start()
        return httpd
    else:
        print(f"[x] Server running on https://{config.ip}:{config.port} forever...")
        httpd.serve_forever()


def main():
    """ 
    Check the supplied configurations and start the Proxy Server. 
    """
    if config.cycle_jarms:
        while True:
            all_configs = grab_valid_configs(return_all=True)
            random.shuffle(all_configs)
            for ssl_config in all_configs:
                httpd = start_server(ssl_config['tls_version'], ssl_config['cipher'], ssl_config['jarm'])
                time.sleep(config.cycle_interval_secs)
                httpd.shutdown()
                time.sleep(3)
    else:
        tls_version, cipher, jarm = grab_valid_configs()
        start_server(tls_version, cipher, jarm)


if __name__ == '__main__':
    main()
