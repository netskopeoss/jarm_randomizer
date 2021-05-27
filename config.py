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

# List of TLS versions supported
ssl_versions = [ssl.PROTOCOL_TLS,
                ssl.PROTOCOL_TLSv1_2]

# API keys for grabbing JARM metrics
SHODAN_KEY = ''
BINARY_EDGE_KEY = ''

# File path settings
paths = {
    'possible_jarms': './possible_jarms.json',
    'valid_configs': './valid_configs.json',
    'invalid_configs': './invalid_configs.json',
    'raw_jarm_stats': './raw_jarm_stats.json',
    'red_team_tool_jarms': './red_team_tool_jarms.json',
}

# Configurations for the proxy
ip = '127.0.0.1'
port = 8443

# Path to the TLS private key and cert files
keyfile = 'key.pem'
certfile = "cert.pem"

# If there is a specific config that is required based on the stats/preference.
# For now, you only have the option to set both or none...will come back and change this
force_ssl_version = None
force_cipher = None

# Cycle JARM configs at certain interval. Avoid setting this and the force_ssl_version and
# force_cipher above. That would not work too well
cycle_jarms = False
cycle_interval_secs = 5
