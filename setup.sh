#!/usr/bin/env bash

#Copyright 2021 Netskope, Inc.
#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
#following conditions are met:
#
#1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
#disclaimer.
#
#2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
#disclaimer in the documentation and/or other materials provided with the distribution.
#
#3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
#products derived from this software without specific prior written permission.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
#INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#Written by Dagmawi Mulugeta

set -e

# Generate a certificate
if [ ! -f cert.pem ]; then
    echo "[x] Generate a certificate and private key file"
    openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
fi

# Get a list of ciphers
echo "[x] Grabbing the list of ciphers that are supported on this system"
openssl ciphers -v | cut -d" " -f1 | sort | uniq > ./ciphers

# Check which server configurations would work
echo "[x] Running setup.py to grab the valid JARMs"
pipenv run python3 setup.py
rm ciphers

# Ready to use
echo "[x] Proxy is ready to use"
echo "[x] Run pipenv run python3 ./main.py to start the proxy server"