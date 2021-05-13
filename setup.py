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
import time
import json
import random
import requests
import urllib3
import shodan

import config
import proxy_handler

from pybinaryedge import BinaryEdge
from jarm.scanner.scanner import Scanner
from http.server import HTTPServer
from threading import Thread

urllib3.disable_warnings()


def start_test_server(version, cipher):
    """ 
    Start a test server on a random port to verify the TLS handshake 
    """
    test_port = random.randint(8000, 9999)
    httpd = HTTPServer((config.ip, test_port), proxy_handler.ProxyHandler)
    httpd.socket = ssl.wrap_socket(
        sock=httpd.socket,
        keyfile=config.keyfile,
        certfile=config.certfile,
        server_side=True,
        ssl_version=version,
        ciphers=cipher
    )
    httpd.server_activate()
    thread = Thread(target=proxy_handler.serve_forever, args=(httpd,))
    thread.setDaemon(True)
    thread.start()
    return test_port, httpd


def grab_unvalidated_ciphers():
    """ 
    Load the cipher list  
    """
    with open('./ciphers', 'r') as _file:
        return sorted([line.strip() for line in _file])


def validate_working_configs():
    """ 
    Load the cipher list after openssl has ran.
    Then test the configurations the proxy can support.
    """
    blocklist = {}
    jarms = []
    for version in config.ssl_versions:
        c_list = grab_unvalidated_ciphers()
        for cipher in c_list:
            print(f"[x] Validating tls {version} and cipher {cipher}")
            try:
                test_port, httpd = start_test_server(version, cipher)
                x = requests.get(f'https://{config.ip}:{test_port}/http://google.com', verify=False)

                jarms.append({
                    'tls_version': version,
                    'cipher': cipher,
                    'jarm': Scanner.scan(config.ip, test_port)[0],
                })
                time.sleep(1)
                httpd.shutdown()
            except Exception as e:
                blocklist[f'{version}-{cipher}'] = str(e)
                if httpd:
                    httpd.shutdown()
    return jarms, blocklist


def get_key(obj, key, default=None):
    """ 
    Utility method to grab nested key
    """
    try:
        result = obj[key.split('.')[0]]
        for k in key.split('.')[1:]:
            result = result[k]
    except Exception as e:
        result = default
    return result


def query_shodan(jarm):
    """ 
    Query Shodan and parse the results
    """
    raw_result = shodan.Shodan(config.SHODAN_KEY).search(f'ssl.jarm:{jarm}')
    cert_orgs = set()
    isps = set()
    cipher_versions = set()
    cipher_names = set()
    hostnames = set()
    domains = set()
    orgs = set()
    cloud_providers = set()
    servers = set()

    for r in raw_result['matches']:
        cert_orgs.add(get_key(r, 'ssl.cert.subject.O', default=''))
        cipher_versions.add(get_key(r, 'ssl.cipher.version', default=''))
        cipher_names.add(get_key(r, 'ssl.cipher.name', default=''))
        orgs.add(get_key(r, 'org', default=''))
        isps.add(get_key(r, 'isp', default=''))
        cloud_providers.add(get_key(r, 'cloud.provider', default=''))
        hostnames.update(get_key(r, 'hostnames', default=[]))
        domains.update(get_key(r, 'domains', default=[]))

        if 'data' in r and len(r['data'].split('Server: ')) > 1:
            servers.add(r['data'].split('Server: ')[1].split('\r\n')[0])

    parsed_results = {
        'total': raw_result['total'],
        'cert_orgs': list(cert_orgs),
        'cipher_versions': list(cipher_versions),
        'cipher_names': list(cipher_names),
        'hostnames': list(hostnames),
        'domains': list(domains),
        'orgs': list(orgs),
        'isps': list(isps),
        'cloud_providers': list(cloud_providers),
        'servers': sorted(list(servers))
    }
    return raw_result, parsed_results


def query_binary_edge(jarm):
    """ 
    Query Binary Edge and parse the results
    """
    raw_result = BinaryEdge(config.BINARY_EDGE_KEY).host_search(f'jarm.jarm_hash:"{jarm}"')
    ips = set()
    ports = set()
    protocols = set()

    for r in raw_result['events']:
        ips.add(get_key(r, 'target.ip', default=''))
        ports.add(get_key(r, 'target.port', default=''))
        protocols.add(get_key(r, 'target.protocol', default=''))

    parsed_results = {
        'total': raw_result['total'],
        'ips': list(ips),
        'ports': list(ports),
        'protocols': list(protocols),
    }
    return raw_result, parsed_results


def check_red_team_usage(jarm):
    """ 
    Checks the JARM against a list of C2 tools here: https://github.com/cedowens/C2-JARM
    """
    with open(config.paths['red_team_tool_jarms']) as _file:
        tools = json.load(_file)
    usage = []
    for tool in tools:
        if jarm == tool['jarm']:
            usage.append(tool)
    return usage


def grab_stats_for_jarms(jarms):
    """ 
    Grab the occurence of JARM on the internet and red team tool usage
    """
    stats = {}
    for jarm in jarms:
        red_team_usage = check_red_team_usage(jarm['jarm'])
        stats[jarm['jarm']] = {
            'raw': {
                'binary_edge': {},
                'shodan': {}
            },
            'red_team_usage': red_team_usage,
            'parsed_be_results': {},
            'parsed_shodan_results': {}
        }
        if config.BINARY_EDGE_KEY:
            raw_be_result, parsed_be_results = query_binary_edge(jarm['jarm'])
            stats[jarm['jarm']]['raw']['binary_edge'] = raw_be_result
            stats[jarm['jarm']]['parsed_be_results'] = parsed_be_results

        if config.SHODAN_KEY:
            raw_shodan_result, parsed_shodan_results = query_shodan(jarm=jarm['jarm'])
            stats[jarm['jarm']]['raw']['shodan'] = raw_shodan_result
            stats[jarm['jarm']]['parsed_shodan_results'] = parsed_shodan_results
    return stats


def reformat_possible_configs(jarms, stats):
    """ 
    Reformat the data into useful stats and configs
    """
    possible_jarms = {}
    valid_configs = []
    for entry in jarms:
        jarm = entry['jarm']
        tls_version = entry['tls_version']
        cipher = entry['cipher']
        valid_configs.append({
            'jarm': jarm,
            'tls_version': tls_version,
            'cipher': cipher,
        })
        if jarm in possible_jarms:
            possible_jarms[jarm]['configs'].append({
                'tls_version': tls_version,
                'cipher': cipher
            })
        else:
            possible_jarms[jarm] = {
                'configs': [
                    {
                        'tls_version': tls_version,
                        'cipher': cipher
                    }
                ],
                'binary_edge': stats[jarm]['parsed_be_results'],
                'shodan': stats[jarm]['parsed_shodan_results'],
                'red_team_usage': stats[jarm]['red_team_usage'],
            }
    return valid_configs, possible_jarms


def write_results_and_configs(jarms, blocklist, stats):
    """ 
    Write the configurations and stats to disk 
    """
    with open(config.paths['invalid_configs'], 'w') as _file:
        json.dump(blocklist, _file, indent=2)

    with open(config.paths['raw_jarm_stats'], 'w') as _file:
        json.dump(stats, _file, indent=2)

    valid_configs, possible_jarms = reformat_possible_configs(jarms, stats)

    with open(config.paths['possible_jarms'], 'w') as _file:
        json.dump(possible_jarms, _file, indent=2)

    with open(config.paths['valid_configs'], 'w') as _file:
        json.dump(valid_configs, _file, indent=2)


def main():
    """ 
    Perform the required setup to run the proxy 
    """
    
    print("[X] Finding all the possible JARMs")
    jarms, blocklist = validate_working_configs()
    print(f"[X] There are {len(set(j['jarm'] for j in jarms))} possible JARMS across {len(jarms)} TLS - Cipher pairs")

    print("[X] Grabbing the metrics for the JARMs...might take a while for long list of JARMs")
    stats = grab_stats_for_jarms(jarms)

    print("[X] Writing the results to disk")
    write_results_and_configs(jarms, blocklist, stats)


if __name__ == '__main__':
    main()
