# Author: Eric Benner <ebenner@vultr.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import json
import re

from os import path
import base64

from cloudinit import log as log
from cloudinit import url_helper
from cloudinit import dmi
from cloudinit import net

# Get logger
LOGGER = log.getLogger(__name__)

# Dict of all API Endpoints
API_MAP = {
    "startup-script": "/latest/startup-script",
    "hostname": "/latest/meta-data/hostname",
    "user-data": "/latest/user-data",
    "mdisk-mode": "/v1/internal/mdisk-mode",
    "root-password": "/v1/internal/root-password",
    "ssh-keys": "/current/ssh-keys",
    "ipv6-dns1": "/current/ipv6-dns1",
    "ipv6-addr": "/current/meta-data/ipv6-addr",
    "v1.json": "/v1.json"
}


# Cache
MAC_TO_NICS = None
METADATA = None


# Cache the metadata for optimization
def get_metadata(params):
    global METADATA
    if not METADATA:
        METADATA = {
            'startup-script': fetch_metadata("startup-script", params),
            'hostname': fetch_metadata("hostname", params),
            'user-data': fetch_metadata("user-data", params),
            'mdisk-mode': fetch_metadata("mdisk-mode", params),
            'root-password': fetch_metadata("root-password", params),
            'ssh-keys': fetch_metadata("ssh-keys", params),
            'ipv6-dns1': fetch_metadata("ipv6-dns1", params),
            'ipv6-addr': fetch_metadata("ipv6-addr", params),
            'v1': json.loads(fetch_metadata("v1.json", params))
        }
    return METADATA


# Read the system information from SMBIOS
def get_sysinfo():
    return {
        'manufacturer': dmi.read_dmi_data("system-manufacturer"),
        'subid': dmi.read_dmi_data("system-serial-number"),
        'product': dmi.read_dmi_data("system-product-name"),
        'family': dmi.read_dmi_data("system-family")
    }


# Get kernel parameters
def get_kernel_parameters():
    if not path.exists("/proc/cmdline"):
        return ""

    file = open("/proc/cmdline")
    content = file.read()
    file.close()

    if "root=" not in content:
        return ""

    return re.sub(r'.+root=', '', content)[1].strip()


# Confirm is Vultr
def is_vultr():
    # VC2, VDC, and HFC use DMI
    sysinfo = get_sysinfo()

    if sysinfo['manufacturer'] == "Vultr":
        return True

    # Baremetal requires a kernel parameter
    if "vultr" in get_kernel_parameters():
        return True

    # An extra fallback if the others fail
    # This needs to be a directory
    if path.exists("/etc/vultr") and path.isdir("/etc/vultr"):
        return True

    return False


# Read cached network config
def get_cached_network_config():
    os.makedirs("/etc/vultr/cache/", exist_ok=True)
    content = ""
    if path.exists("/etc/vultr/cache/network"):
        file = open("/etc/vultr/cache/network", "r")
        content = file.read()
        file.close()
    return content


# Cached network config
def cache_network_config(config):
    os.makedirs("/etc/vultr/cache/", exist_ok=True)
    file = open("/etc/vultr/cache/network", "w")
    file.write(json.dumps(config))
    file.close()


# Read Metadata endpoint
def read_metadata(params):
    response = url_helper.readurl(
        params['url'], timeout=params['timeout'], retries=params['retries'],
        headers={'Metadata-Token': 'vultr'},
        sec_between=params['wait'])

    if not response.ok():
        raise RuntimeError("Failed to connect to %s: Code: %s" %
                           params['url'], response.code)

    return response.contents.decode()


# Translate flag to endpoint
def get_url(url, flag):
    if flag in API_MAP:
        return url + API_MAP[flag]

    if "app-" in flag or "md-" in flag:
        return url + "/v1/internal/" + flag

    return ""


# Get Metadata by flag
def fetch_metadata(flag, params):
    req = dict(params)
    req['url'] = get_url(params['url'], flag)

    if req['url'] == "":
        raise RuntimeError("Not a valid endpoint. Flag: %s" % flag)

    return read_metadata(req)


# Convert macs to nics
def get_interface_name(mac):
    global MAC_TO_NICS

    # Define it if empty
    if not MAC_TO_NICS:
        MAC_TO_NICS = net.get_interfaces_by_mac()

    if mac not in MAC_TO_NICS:
        return None

    return MAC_TO_NICS.get(mac)


# Generate network configs
def generate_network_config(config):
    md = get_metadata(config)

    network = {
        "version": 1,
        "config": [
            {
                "type": "nameserver",
                "address": [
                    "108.61.10.10"
                ]
            }
        ]
    }

    if len(md['v1']['interfaces']) > 0:
        interface = md['v1']['interfaces'][0]
        interface_name = get_interface_name(interface['mac'])
        if not interface_name:
            raise RuntimeError("Interface: %s not found" % interface['mac'])

        netcfg = {
            "name": interface_name,
            "type": "physical",
            "mac_address": interface['mac'],
            "accept-ra": 1,
            "subnets": [
                {
                    "type": "static",
                    "control": "auto",
                    "address": interface['ipv4']['address'],
                    "gateway": interface['ipv4']['gateway'],
                    "netmask": interface['ipv4']['netmask']
                },
                {
                    "type": "dhcp6",
                    "control": "auto"
                },
            ]
        }

        network['config'].append(netcfg)

    if len(md['v1']['interfaces']) > 1:
        interface = md['v1']['interfaces'][1]
        interface_name = get_interface_name(interface['mac'])
        if not interface_name:
            raise RuntimeError("Interface: %s not found" % interface['mac'])

        netcfg = {
            "name": interface_name,
            "type": "physical",
            "mac_address": interface['mac'],
            "accept-ra": 1,
            "subnets": [
                {
                    "type": "static",
                    "control": "auto",
                    "address": interface['ipv4']['address'],
                    "netmask": interface['ipv4']['netmask']
                }
            ]
        }

        network['config'].append(netcfg)

    return network


# Generate the vendor config
# This configuration is to replicate how
# images are deployed on Vultr before Cloud-Init
def generate_config(config):
    md = get_metadata(config)

    # Grab the startup script
    script = md['startup-script']
    if script != "":
        script = base64.b64encode(
            script.encode("ascii")).decode("ascii")

    # Grab the rest of the details
    rootpw = md['root-password']

    # Start the template
    # We currently setup root, this will eventually change
    config_template = {
        "package_upgrade": "true",
        "disable_root": 0,
        "ssh_pwauth": 1,
        "chpasswd": {
            "expire": False,
            "list": [
                "root:" + rootpw
            ]
        },
        "system_info": {
            "default_user": {
                "name": "root"
            }
        },
        "network": generate_network_config(config)
    }

    # Set the startup script
    if script != "":
        # Write user scripts to a temp file
        config_template['write_files'] = [
            {
                "encoding": "b64",
                "content": script,
                "owner": "root:root",
                "path": "/tmp/startup-vultr.sh",
                "permissions": "0755"
            }
        ]

        # Add a command to runcmd to execute script added above
        config_template['runcmd'] = config_template['runcmd'] + [
            "/tmp/startup-vultr.sh &> /var/log/vultr-boot.log",
            "rm -f /tmp/startup-vultr.sh"
        ]

    return config_template

# vi: ts=4 expandtab
