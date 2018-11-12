# ACOS 2.7.x Ansible Playbooks

It is a combination of Ansible Playbooks and Modules in YAML and Python library for automating ACOS 2.7.x operations.

## Installation

### Requirements
* Python 2.7
* Ansible 2.6.4

### Configuration
Update the ansible.cfg [default location: /etc/ansible/ansible.cfg] file with this project's library. Alternatively you could create a separate ansible.cfg and pass it at runtime.

```
...
[defaults]

# some basic default values...

#inventory      = /etc/ansible/hosts
library        = /Users/deb/a10-ansible-acos27x/library
module_utils   = /Users/deb/a10-ansible-acos27x/library
#remote_tmp     = ~/.ansible/tmp
#local_tmp      = ~/.ansible/tmp
#plugin_filters_cfg = /etc/ansible/plugin_filters.yml
...
```

Create Host group in hosts file [default location: /etc/ansible/hosts]

```
[a10devices]
172.168.10.10
172.168.10.11
```

## Usage

The resouces are created in a sequence: real servers, service groups, virtual servers and health monitor. To create all of them, change the variables in each role according to your ACOS setup. E.g.


Real server task file
```
---
- debug:
    msg: "{{inventory_hostname}}"

- name: Create a realserver
  a10_server_v2:
    host: "{{inventory_hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    state: "{{state}}"
    validate_certs: no
    partition: "{{partition}}"
    server_name: "{{rserver_name}}"
    server_ip: "{{rserver_ip}}"
    server_status: "{{server_status}}"
    server_ports:
        - port_num: "{{rserver_port}}"
          protocol: "{{rserver_protocol}}"

```

Real server var file
```
---
# Real server variables
username: admin
state: present
server_status: enabled
partition: ""
rserver_name: webserver2
rserver_ip: 172.168.10.10
rserver_port: 80
rserver_protocol: tcp

```

To run real server role tasks
```
ansible-playbook rserver.yml
```

To run all the roles tasks
```
ansible-playbook play.yml
```

## Development

When an ansible module is passed multiple optional arguments the YAML needs to be updated along with var files accordingly. E.g. if two real servers are to be added to a service group then the service group task file would look like this:
```
---
- debug:
    msg: "{{inventory_hostname}}"
- name: Create a service group
  a10_service_group_v2:
    validate_certs: no
    host: "{{inventory_hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    state: "{{state}}"
    partition: "{{partition}}"
    service_group: "{{servicegroup_name}}"
    servers:
       - server: "{{real_server_name}}"
         port: "{{real_server_port}}"
       - server: "{{real_server_name2}}"
         port: "{{real_server_port2}}"

```

And the var file would look like this:
```
---
username: admin
state: present
partition: ""
servicegroup_name: CSPOOL
real_server_name: webserver
real_server_port: 80
real_server_name2: webserver2
real_server_port2: 80
```
