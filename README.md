<img src="ntrl.png" alt="Netskope Threat Labs logo" width="150"/>

# JARM Randomizer

<img src="logo.png" alt="JARM Randomizer" width="150">

## Introduction

JARM Randomizer is a Python3 tool that iterates over supported server side TLS version and Cipher suites to defeat JARM based fingerprinting.
This tool was open sourced as part of [JARM Randomizer: Evading JARM Fingerprinting](https://conference.hitb.org/hitbsecconf2021ams/sessions/commsec-jarm-randomizer-evading-jarm-fingerprinting/ "JARM Randomizer: Evading JARM Fingerprinting") for HiTB Amsterdam 2021.

## Setup

### Dependencies

This tool relies on the following to be installed on the system:

- [pipenv](https://pypi.org/project/pipenv/)
- [Python 3.9](https://docs.python.org/3/whatsnew/3.9.html)
- [openssl](https://www.openssl.org/)

Once these dependencies has been installed, run `pipenv install` in the root directory to setup the virtual environment and install the required dependencies.

## Usage

### Configuration file

The `config.py` file present in the root directory can be modified to match the desired configurations.

To set what network/port you would like the proxy to serve, change these configurations:

```python
# Configurations for the proxy
ip = '0.0.0.0'
port = 8443
```

To set what private key and SSL/TLS certificate path, change these configurations:

```python
# Path to the TLS private key and cert files
keyfile = 'key.pem'
certfile = "cert.pem"
```

During the setup process, the proxy will read in and output certain required files.
To tweak these file paths (Possibly to output them all in an `output` directory), change these configurations:

```python
# File path settings
paths = {
    'possible_jarms': './possible_jarms.json', # The output file that has the possible JARMs, calid TLS - Cipher pairs, and general stats of occurence on the internet.
    'valid_configs': './valid_configs.json', # A lighter version of the possible_jarms.json that just has the TLS - Cipher pairs. 
    'invalid_configs': './invalid_configs.json', # A list of TLS - Cipher pairs that the proxy can not support.
    'raw_jarm_stats': './raw_jarm_stats.json', # A raw dump of everything the proxy found during setup. Helpful for debugging and research.
    'red_team_tool_jarms': './red_team_tool_jarms.json', # An input file contianing JARMs for red team tools that was mapped from https://github.com/cedowens/C2-JARM.
}
```

If these API keys are provided, the setup process will also check the possible JARMs for occurence on the internet.

```python
# API keys for grabbing JARM metrics
SHODAN_KEY = ''
BINARY_EDGE_KEY = ''
```

If there is a specific TLS - Cipher pair that is desired, change these configurations to match.

```python
# If there is a specific config that is required based on the stats/preference.
# For now, you only have the option to set both or none...will come back and change this
force_ssl_version = None # E.g., 2
force_cipher = None # E.g., 'ECDHE-RSA-CHACHA20-POLY1305'
```

If you would like to cycle through the TLS - Cipher pairs that are supported on a system, change these configurations to match.

```python
# Cycle JARM configs at certain interval. Avoid setting this and the force_ssl_version and
# force_cipher above. That would not work too well
cycle_jarms = True
cycle_interval_secs = 5
```

### Grabbing valid configurations

Once the `config.py` has been tweaked to match the desired configurations, run the following command to setup the proxy

```bash
ubuntu@jarm:~/jarm_randomizer$ chmod u+x ./setup.sh && ./setup.sh

[x] Grabbing the list of ciphers that are supported on this system
[x] Running setup.py to grab the valid JARMs
[X] Finding all the possible JARMs
[x] Validating tls 2 and cipher AES128-GCM-SHA256
127.0.0.1 - - [11/May/2021 17:32:25] "GET /http://google.com HTTP/1.1" 200 -
[x] Validating tls 2 and cipher AES128-SHA
...
[X] There are 27 possible JARMS across 70 TLS - Cipher pairs
[X] Grabbing the metrics for the JARMs...might take a while for long list of JARMs
[X] Writing the results to disk
[x] Proxy is ready to use
[x] Run python3 ./main.py to start the proxy server
```

If there is no private key and certificate at the specified file paths, this script will generate a self signed certificate for testing purposes.

### Running Proxy

Once the `config.py` has been updated to match the desire configurations, and `setup.sh` has been run, the proxy is ready to use.

Run the following command to start running the proxy

```bash
ubuntu@jarm:~/jarm_randomizer$ pipenv run python3 ./main.py

[x] Selected configs: TLS -> 5, Cipher -> ECDHE-RSA-CHACHA20-POLY1305, JARM -> 3fd3fd0003fd3fd0003fd3fd3fd3fd02098c5f1b1aef82f7daaf9fed36c4e8
[x] Server running on https://0.0.0.0:8443 forever...
```

### Testing the proxy

If we run the following command, we should recieve a valid proxied response

```bash
ubuntu@jarm:~$ curl -k https://127.0.0.1:8443/http://google.com
```

In the above example add `-k` if the certificate was self signed.

The `proxy_handler.py` file contains logic to handle the specific proxy request.
If other proxy specific changes are required, change this script to match.

## Future Improvements

We have ongoing research to identify areas of improvment around JARM randomizer including:

- Scale to generate larger list of signatures
- Ability to mimic a targeted server’s JARM
- Dig deeper into the extensions
- Stick sessions to not rotate configuration based on IP address

For the latest research around JARM Randomizer, check out our [Blog](https://www.netskope.com/blog/category/netskope-threat-labs "Netskope Threat Labs Blog")

## Feedback

Any and all feedback around JARM Randomizer are welcome:

- [Twitter](https://twitter.com/dagmulu)
- [Linkedin](https://www.linkedin.com/in/dmulugeta)
