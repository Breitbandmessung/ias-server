# ias-server #

Internet Access Speed (IAS) measurement server. The repository is used by the service [breitbandmessung.de](https://breitbandmessung.de) of the German Federal Network Agency (Bundesnetzagentur), and originates in the BEREC [Net Neutrality (NN) Reference Measurement System](https://github.com/net-neutrality-tools/nntool).

### Build dependencies ###
* Linux
* make
* cmake
* g++
* liblog4cpp5-dev
* libssl-dev
* libtool
* nopoll (see https://github.com/zafaco/nopoll)

### Building ###

1. Build `nopoll` (see https://github.com/zafaco/nopoll)
2. Run `INSTALL`

### Execution ###

1. Create dir `/etc/ias-server/`
2. Copy trace.ini to `/etc/ias-server/`
3. Customize and deploy `config.json` to `/etc/ias-server/`
4. Create dir `/var/log/ias-server/`
5. Create dir `/var/opt/ias-server/certs/{my_fqdn}/`
6. Deploy Certificate with filename `{my_fqdn}.crt` to the folder created in step 5.
7. Deploy Private Key with filename `{my_fqdn}.key` to the folder created in step 5.

---------------

# License #

`ias-server` is released under the [AGPLv3](https://www.gnu.org/licenses/agpl-3.0.txt)

Copyright (C) 2016-2025 zafaco GmbH

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3 
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.