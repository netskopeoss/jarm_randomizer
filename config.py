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
