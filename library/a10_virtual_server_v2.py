#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb virtual server objects
(c) 2014, Mischa Peters <mpeters@a10networks.com>

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
module: a10_virtual_server
version_added: 1.8
short_description: Manage A10 Networks devices' virtual servers
description:
    - Manage slb virtual server objects on A10 Networks devices via aXAPI
author: "Debabrata Das"
notes:
    - Requires A10 Networks aXAPI 2.1
requirements: []
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
    default: null
    aliases: []
    choices: []
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    default: null
    aliases: ['user', 'admin']
    choices: []
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    default: null
    aliases: ['pass', 'pwd']
    choices: []
  partition:
    description:
      - L3V partition to add these servers to
    required: false
    default: null
    choices: []
  virtual_server:
    description:
      - slb virtual server name
    required: true
    default: null
    aliases: ['vip', 'virtual']
    choices: []
  virtual_server_ip:
    description:
      - slb virtual server ip address
    required: false
    default: null
    aliases: ['ip', 'address']
    choices: []
  virtual_server_status:
    description:
      - slb virtual server status
    required: false
    default: enable
    aliases: ['status']
    choices: ['enabled', 'disabled']
  acl_id:
    description:
      - acl bound to the virtual server, used for wild card vips
    required: false
    default: null
    aliases: ['acl_id']
  acl_name:
    description:
      - acl name bound to the ipv6 virtual server, used for ipv6 wild card vips
    required: false
    default: null
  disable_vserver_on_condition:
    description:
      - disable VIP on
        0 means never
        1 means when_any_port_down
        2 means when_all_ports_down
    required: false
    default: 0
  redistribution_flagged:
    description:
      - flag this VIP for redistribution through routing protocols
    required: false
    default: False
    choices: ['True','False']
  virtual_server_ports:
    description:
      - A list of ports to create for the virtual server. Each list item should be a
        dictionary which specifies the C(port:) and C(type:), but can also optionally
        specify the C(service_group:) as well as the C(status:). See the examples
        below for details. This parameter is required when C(state) is C(present).
    required: false
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    default: "no"
    choices: ["yes", "no"]
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new virtual server
- a10_virtual_server:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_DEMO
    virtual_server: vserver1
    virtual_server_ip: 1.1.1.1
    virtual_server_ports:
      - port: 80
        protocol: TCP
        service_group: sg-80-tcp
      - port: 443
        protocol: HTTPS
        service_group: sg-443-https
      - port: 8080
        protocol: http
        status: disabled
        state: present

# Create a new wild card virtual server
- a10_virtual_server:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_DEMO
    virtual_server: vserver2
    virtual_server_ip: 0.0.0.0
    acl_id: 101
    virtual_server_ports:
      - port: 443
        protocol: HTTPS
        service_group: sg-443-https

# Create a new IPv6 wild card virtual server
- a10_virtual_server:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_DEMO
    virtual_server: vserver_v6
    virtual_server_ip: 0::0
    acl_name: v6_acl
    virtual_server_ports:
      - port: 443
        protocol: HTTPS
        service_group: sg-v6-443-https



'''

VALID_PORT_FIELDS = ['port', 'protocol', 'service_group', 'status','tcp_template','tcp_proxy_template','ssl_session_id_persistence_template','ha_connection_mirror','extended_stats','source_nat','cookie_persistence_template','aflex_list','http_template','client_ssl_template','server_ssl_template','acl_natpool_binding_list','source_ip_persistence_template','send_reset','name','direct_server_return','default_selection', 'state']

def validate_ports(module, ports):
    for item in ports:
        for key in item:
            if key not in VALID_PORT_FIELDS:
                module.fail_json(msg="invalid port field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_FIELDS)))

        # validate the port number is present and an integer
        if 'port' in item:
            try:
                item['port'] = int(item['port'])
            except:
                module.fail_json(msg="port definitions must be integers")
        else:
            module.fail_json(msg="port definitions must define the port field")

        AXAPI_VPORT_PROTOCOLS['dns-udp'] = 18

        # validate the port protocol is present, and convert it to
        # the internal API integer value (and validate it)
        if 'protocol' in item:
            protocol = axapi_get_vport_protocol(item['protocol'])
            if not protocol:
                module.fail_json(msg="invalid port protocol, must be one of: %s" % ','.join(AXAPI_VPORT_PROTOCOLS))
            else:
                item['protocol'] = protocol
        else:
            module.fail_json(msg="port definitions must define the port protocol (%s)" % ','.join(AXAPI_VPORT_PROTOCOLS))

        # convert the status to the internal API integer value
        if 'status' in item:
            item['status'] = axapi_enabled_disabled(item['status'])
        else:
            item['status'] = 1

        # ensure the service_group field is at least present
        # if 'service_group' not in item:
        #     item['service_group'] = ''

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
            partition=dict(type='str', aliases=['partition','part']),
            virtual_server=dict(type='str', aliases=['vip', 'virtual'], required=True),
            virtual_server_ip=dict(type='str', aliases=['ip', 'address'], required=False),
            virtual_server_status=dict(type='str', default='enabled', aliases=['status'], choices=['enabled', 'disabled']),
            disable_vserver_on_condition=dict(type='str', choices=['0','1','2'], required=False, default='0'),
            redistribution_flagged=dict(type='str', choices=['True','False'], required=False, default='False'),
            acl_id=dict(type='str', required=False, default=None),
            acl_name=dict(type='str', required=False, default=None),
            virtual_server_ports=dict(type='list', required=False, default=[]),
            ha_group=dict(type='list',required=False, default=None),
            vrid=dict(type='int', required=False, default=None)
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
    slb_virtual = module.params['virtual_server']
    slb_virtual_ip = module.params['virtual_server_ip']
    slb_virtual_status = module.params['virtual_server_status']
    slb_virtual_ports = module.params['virtual_server_ports']
    redistribution_flagged = module.params['redistribution_flagged']
    acl_id = module.params['acl_id']
    acl_name = module.params['acl_name']
    disable_vserver_on_condition = module.params['disable_vserver_on_condition']
    ha_group = module.params['ha_group']
    vrid = module.params['vrid']


    if slb_virtual is None:
        module.fail_json(msg='virtual_server is required')

    validate_ports(module, slb_virtual_ports)

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    slb_virtual_data = axapi_call(module, session_url + '&method=slb.virtual_server.search', json.dumps({'name': slb_virtual}))
    slb_virtual_exists = not axapi_failure(slb_virtual_data)

    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active',json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

    changed = False
    if state == 'present':

        json_post = {
            'virtual_server': {
                'name': slb_virtual,
                'status': axapi_enabled_disabled(slb_virtual_status),
                'vport_list': slb_virtual_ports
            }
        }

        # if redistribution_flagged was passed in
        if redistribution_flagged == 'True':
            json_post['virtual_server']['redistribution_flagged'] = 1
        else:
            json_post['virtual_server']['redistribution_flagged'] = 0

        # if disable on condition passed in
        if disable_vserver_on_condition:
            json_post['virtual_server']['disable_vserver_on_condition'] = disable_vserver_on_condition

        # if acl id or acl name was passed in bind it to the vip, otherwise assign the ip address passed in
        if acl_id or acl_name:
            if acl_id:
                json_post['virtual_server']['acl_id'] = acl_id
            else:
                json_post['virtual_server']['acl_name'] = acl_name
        # else:
        #     json_post['virtual_server']['address'] = slb_virtual_ip

        if slb_virtual_ip:
                json_post['virtual_server']['address'] = slb_virtual_ip

        if ha_group is not None:
            for item in ha_group:
                json_post['virtual_server']['ha_group'] = {}
                json_post['virtual_server']['ha_group']['ha_group_id'] = item['ha_group_id']
                json_post['virtual_server']['ha_group']['dynamic_server_weight'] = item['dynamic_server_weight']
                json_post['virtual_server']['ha_group']['status'] = item['status']

        if vrid is not None:
            json_post['virtual_server']['vrid'] = vrid

        # before creating/updating we need to validate that any
        # service groups defined in the ports list exist since
        # since the API will still create port definitions for
        # them while indicating a failure occurred
        checked_service_groups = []
        for port in slb_virtual_ports:
            if 'service_group' in port and port['service_group'] not in checked_service_groups:
                # skip blank service group entries
                if port['service_group'] == '':
                    continue
                result = axapi_call(module, session_url + '&method=slb.service_group.search', json.dumps({'name': port['service_group']}))
                if axapi_failure(result):
                    module.fail_json(msg="the service group %s specified in the ports list does not exist" % port['service_group'])
                checked_service_groups.append(port['service_group'])

        if not slb_virtual_exists:
            if not slb_virtual_ip:
                module.fail_json(msg='you must specify an IP address when creating a server')
            result = axapi_call(module, session_url + '&method=slb.virtual_server.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the virtual server: %s" % result['response']['err']['msg'])
            changed = True
        else:

            # Remove port list and update only server level attributes
            try:
                json_post['virtual_server'].pop('vport_list')
            except KeyError, e:
                pass

            result = axapi_call(module, session_url + '&method=slb.virtual_server.update', json.dumps(json_post))

            # Create server port level json object
            vserver_port_json = {
                'name': slb_virtual
            }

            defined_ports = slb_virtual_data.get('virtual_server', {}).get('vport_list', [])

            def port_exists(srv_port):
                ''' Checks to determine if the port already exists in the server conf
                '''
                for defined_port in defined_ports:
                    if defined_port['port'] == srv_port['port']:
                        return True
                return False

            for vport in slb_virtual_ports:
                vserver_port_json["vport"] = vport
                if port['state'] == 'present':
                    if port_exists(vport):
                        result = axapi_call(module, session_url + '&method=slb.virtual_server.vport.update', json.dumps(vserver_port_json))
                        if axapi_failure(result):
                            module.fail_json(msg="failed to create the virtual server port: %s" % result['response']['err']['msg'])
                        changed = True
                    else:
                        result = axapi_call(module, session_url + '&method=slb.virtual_server.vport.create', json.dumps(vserver_port_json))
                        if axapi_failure(result):
                            module.fail_json(msg="failed to update the virtual server port: %s" % result['response']['err']['msg'])
                        changed = True
                else:
                    result = axapi_call(module, session_url + '&method=slb.virtual_server.vport.delete', json.dumps(vserver_port_json))
                    changed = True

        # if we changed things, get the full info regarding
        # the service group for the return data below
        if changed:
            result = axapi_call(module, session_url + '&method=slb.virtual_server.search', json.dumps({'name': slb_virtual}))
        else:
            result = slb_virtual_data
    elif state == 'absent':
        if slb_virtual_exists:
            result = axapi_call(module, session_url + '&method=slb.virtual_server.delete', json.dumps({'name': slb_virtual}))
            changed = True
        else:
            result = dict(msg="the virtual server was not present")

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
