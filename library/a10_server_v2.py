#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
(c) 2014

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

DOCUMENTATION = '''
---
module: a10_server_v2
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage slb server objects on A10 Networks devices via aXAPI
author: Mischa Peters (@mischapeters) with modifications by Fadi Hafez and Debabrata Das
notes:
    - Requires A10 Networks aXAPI 2.1
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    aliases: ['user', 'admin']
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    aliases: ['pass', 'pwd']
  partition:
    description:
      - L3V partition to add these servers to
    required: false
    default: null
    choices: []
  server_name:
    description:
      - slb server name
    required: true
    aliases: ['server']
  server_ip:
    description:
      - slb server IP address
    required: false
    default: null
    aliases: ['ip', 'address']
  server_status:
    description:
      - slb virtual server status
    required: false
    default: enabled
    aliases: ['status']
    choices: ['enabled', 'disabled']
  server_ports:
    description:
      - A list of ports to create for the server. Each list item should be a
        dictionary which specifies the C(port:) and C(protocol:) and C(health_monitor:), but can also optionally
        specify the C(status:). See the examples below for details. This parameter is
        required when C(state) is C(present).  Health Monitor must already exist.
    required: false
    default: null
  server_hm:
    description:
      - A health monitor name to bind to this server.  The health monitor must already exist.
    required: false
    default: null
  state:
    description:
      - create, update or remove slb server
    required: false
    default: present
    choices: ['present', 'absent']
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    version_added: 2.2
    default: 'no'
    choices: ['yes', 'no']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    version_added: 2.2
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new server
- a10_server:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    server: test
    server_ip: 1.1.1.100
    server_hm: hm_icmp
    server_ports:
      - port_num: 8080
        protocol: tcp
        health_monitor: ws_hm_http
        state: present
      - port_num: 8443
        protocol: TCP
        health_monitor: ws_hm_https
        state: present

'''

VALID_PORT_FIELDS = ['port_num', 'protocol', 'status', 'health_monitor', 'state']

def validate_ports(module, ports, s_url):
    for item in ports:
        for key in item:
            if key not in VALID_PORT_FIELDS:
                module.fail_json(msg="invalid port field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_FIELDS)))

        # validate the port number is present and an integer
        if 'port_num' in item:
            try:
                item['port_num'] = int(item['port_num'])
            except:
                module.fail_json(msg="port_num entries in the port definitions must be integers")
        else:
            module.fail_json(msg="port definitions must define the port_num field")

        # validate the port protocol is present, and convert it to
        # the internal API integer value (and validate it)
        if 'protocol' in item:
            protocol = axapi_get_port_protocol(item['protocol'])
            if not protocol:
                module.fail_json(msg="invalid port protocol, must be one of: %s" % ','.join(AXAPI_PORT_PROTOCOLS))
            else:
                item['protocol'] = protocol
        else:
            module.fail_json(msg="port definitions must define the port protocol (%s)" % ','.join(AXAPI_PORT_PROTOCOLS))


        # validate that if the health monitor has been passed it, it exists on the system already
        if 'health_monitor' in item:
            # if 'none' was the value of the health_monitor then do a 'no health-monitor'
            if item['health_monitor'] == 'no':
                item['health_monitor'] = ''
            else:
                json_post = {"name": item['health_monitor']}
                result = axapi_call(module, s_url + '&method=slb.hm.search', json.dumps(json_post))
                if ('response' in result and result['response']['status'] == 'fail'):
                    module.fail_json(msg=result['response']['err']['msg'])
        else:
            item['health_monitor'] = "(default)"


        # convert the status to the internal API integer value
        if 'status' in item:
            if item['status'] not in ('enabled', 'disabled'):
                module.fail_json(msg="Allowed values for port state are enabled and disabled)")
            item['status'] = axapi_enabled_disabled(item['status'])
        else:
            item['status'] = 1

        if 'state' in item:
            if item['state'] not in ('present', 'absent'):
                module.fail_json(msg="Allowed values for port state are present and absent)")
        else:
            item['state'] = 'present'


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            server_name=dict(type='str', aliases=['server'], required=True),
            server_ip=dict(type='str', aliases=['ip', 'address']),
            server_status=dict(type='str', default='enabled', aliases=['status'], choices=['enabled', 'disabled']),
            server_ports=dict(type='list', aliases=['port'], default=[]),
            server_hm=dict(type='str', aliases=['health_monitor']),
            slow_start=dict(type='str', required=False, default=None)
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    part = module.params['partition']
    state = module.params['state']
    write_config = module.params['write_config']
    slb_server = module.params['server_name']
    slb_server_ip = module.params['server_ip']
    slb_server_status = module.params['server_status']
    slb_server_ports = module.params['server_ports']
    slb_server_hm = module.params['server_hm']
    slb_server_slow_start = module.params['slow_start']

    if slb_server is None:
        module.fail_json(msg='server_name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    slb_server_data = axapi_call(module, session_url + '&method=slb.server.search', json.dumps({'name': slb_server}))
    slb_server_exists = not axapi_failure(slb_server_data)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

    # validate the ports data structure
    validate_ports(module, slb_server_ports, session_url)

    json_post = {
        'server': {
            'name': slb_server,
        }
    }

    # add optional module parameters
    if slb_server_ip:
        json_post['server']['host'] = slb_server_ip

    if slb_server_ports:
        json_post['server']['port_list'] = slb_server_ports

    if slb_server_hm:
        json_post['server']['health_monitor'] = slb_server_hm

    if slb_server_status:
        json_post['server']['status'] = axapi_enabled_disabled(slb_server_status)

    if slb_server_slow_start:
        json_post['server']['slow_start'] = slb_server_slow_start

    changed = False
    if state == 'present':
        if not slb_server_exists:
            if not slb_server_ip:
                module.fail_json(msg='you must specify an IP address when creating a server')
            result = axapi_call(module, session_url + '&method=slb.server.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the server: %s" % result['response']['err']['msg'])
            changed = True
        else:

            # Remove port list and update only server level attributes
            port_list = json_post['server'].pop('port_list')
            result = axapi_call(module, session_url + '&method=slb.server.update', json.dumps(json_post))

            # Create server port level json object
            server_port_json = {
                'name': slb_server
            }

            defined_ports = slb_server_data.get('server', {}).get('port_list', [])

            def port_exists(srv_port):
                ''' Checks to determine if the port already exists in the server conf
                '''
                for defined_port in defined_ports:
                    if defined_port['port_num'] == srv_port['port_num']:
                        return True
                return False

            for port in slb_server_ports:
                server_port_json["port"] = port
                if port['state'] == 'present':
                    if port_exists(port):
                        result = axapi_call(module, session_url + '&method=slb.server.port.update', json.dumps(server_port_json))
                        if axapi_failure(result):
                            module.fail_json(msg="failed to create the server port: %s" % result['response']['err']['msg'])
                        changed = True
                    else:
                        result = axapi_call(module, session_url + '&method=slb.server.port.create', json.dumps(server_port_json))
                        if axapi_failure(result):
                            module.fail_json(msg="failed to update the server port: %s" % result['response']['err']['msg'])
                        changed = True
                else:
                    result = axapi_call(module, session_url + '&method=slb.server.port.delete', json.dumps(server_port_json))
                    changed = True

        # if we changed things, get the full info regarding
        # the service group for the return data below
        if changed:
            result = axapi_call(module, session_url + '&method=slb.server.search', json.dumps({'name': slb_server}))
        else:
            result = slb_server_data
    elif state == 'absent':
        if slb_server_exists:
            result = axapi_call(module, session_url + '&method=slb.server.delete', json.dumps({'name': slb_server}))
            changed = True
        else:
            result = dict(msg="the server was not present")

    # if the config has changed, save the config unless otherwise requested
    if changed and write_config:
        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
        if axapi_failure(write_result):
            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out of the session nicely and exit
    axapi_call(module, session_url + '&method=session.close')
    module.exit_json(changed=changed, content=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *

if __name__ == '__main__':
    main()
