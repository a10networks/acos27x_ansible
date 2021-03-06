#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks objects
(c) 2016, Debabrata Das <ddas@a10networks.com>

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
module: a10_udp_template
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage udp template objects on A10 Networks devices via aXAPI
author: Fadi Hafez using works of Mischa Peters
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
      - L3V partition to add the template to.  Will be added to 'shared' if not specified
    required: false
    default: null
    choices: []
  state:
    description:
      - create, update or remove udp template
    required: false
    default: present
    choices: ['present', 'absent']
  name:
    description:
      - name of the template
    required: true
  idle_timeout:
    description:
      - number of secs a connection can remain idle before ACOS terminates it
    required: false
    default: null
  aging_type:
    description:
      - Specify how quickly sessions are terminated.
        0 = None
        1 = Immediate
        2 = Short-Lived
    required: false
    default: 0
    choices: [0, 1, 2]
  short_lived:
    description:
      - Short live age
        range 1-31
    required: false
    default: 0
  reselect:
    description:
      - Select another server if server is down
    required: false
    default: false
    choices: [true, false]
  stateless_cur_con_timeout:
    description:
      - Stateless current connection timeout in seconds
        range 5-120
    required: false
    default: 0
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    version_added: 2.2
    default: "no"
    choices: ["yes", "no"]
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
# Create a new udp Template
- a10_udp_template:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_udp_templ
    aging_type: 2
    idle_timeout: 1000
'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            idle_timeout=dict(type='int', default=120, required=False),
            aging_type=dict(type='int', default=0, required=False),
            #aging_type=dict(type='int', default=0, choices=['0','1','2'], required=False),
            short_lived=dict(type='int', default=0, required=False),
            reselect=dict(type='bool', default=False),
            stateless_cur_con_timeout=dict(type='int', default=0, required=False),
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
    name = module.params['name']

    idle_timeout = module.params['idle_timeout']
    aging_type = module.params['aging_type']
    short_lived = module.params['short_lived']
    reselect = module.params['reselect']
    stateless_cur_con_timeout = module.params['stateless_cur_con_timeout']

    if name is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])


    # populate the json body for the creation of the udp template
    json_post = {
        'udp_template': {
            'name': name,
        }
    }

    if idle_timeout is not None:
        json_post['udp_template']['idle_timeout'] = idle_timeout

    if aging_type is not None:
        json_post['udp_template']['aging_type'] = aging_type

    if short_lived is not None and aging_type is not None:
        json_post['udp_template']['short_lived'] = short_lived
    else:
        json_post['udp_template']['short_lived'] = 0

    if reselect is None or reselect == False:
        json_post['udp_template']['reselect'] = 0
    else:
        json_post['udp_template']['reselect'] = 1

    if stateless_cur_con_timeout is not None:
        json_post['udp_template']['stateless_cur_con_timeout'] = stateless_cur_con_timeout
    else:
        json_post['udp_template']['stateless_cur_con_timeout'] = 0



    # check to see if this udp_template exists
    udp_template_data = axapi_call(module, session_url + '&method=slb.template.udp.search', json.dumps({'name': name}))
    udp_template_exists = not axapi_failure(udp_template_data)

    changed = False
    if state == 'present':

        if not udp_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.udp.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the udp template: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=slb.template.udp.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to update the udp template: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if udp_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.udp.delete', json.dumps({'name': name}))
            changed = True
        else:
            result = dict(msg="the udp template was not present")

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
