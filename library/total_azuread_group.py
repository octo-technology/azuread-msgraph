#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, TOTAL SA

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'metadata_version': '1.1'
}

DOCUMENTATION = '''
---
module: grafana_team
author:
  - Rémi REY (@rrey)
version_added: "2.10"
short_description: Manage Grafana Teams
description:
  - Create/update/delete Grafana Teams through the Teams API.
  - Also allows to add members in the team (if members exists).
  - The Teams API is only available starting Grafana 5 and the module will fail if the server version is lower than version 5.
options:
  name:
    description:
      - The name of the Grafana Team.
    required: true
    type: str
  email:
    description:
      - The mail address associated with the Team.
    required: true
    type: str
  members:
    description:
      - List of team members (emails).
      - The list can be enforced with C(enforce_members) parameter.
    type: list
    elements: str
  state:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: present
    type: str
    choices: ["present", "absent"]
  enforce_members:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: False
    type: bool
extends_documentation_fragment:
- community.grafana.basic_auth
- community.grafana.api_key
'''

EXAMPLES = '''
---
- name: Create a team
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      state: present

- name: Create a team with members
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      members:
          - john.doe@example.com
          - jane.doe@example.com
      state: present

- name: Create a team with members and enforce the list of members
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      members:
          - john.doe@example.com
          - jane.doe@example.com
      enforce_members: yes
      state: present

- name: Delete a team
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      state: absent
'''

RETURN = '''
---
team:
    description: Information about the Team
    returned: On success
    type: complex
    contains:
        avatarUrl:
            description: The url of the Team avatar on Grafana server
            returned: always
            type: str
            sample:
                - "/avatar/a7440323a684ea47406313a33156e5e9"
        email:
            description: The Team email address
            returned: always
            type: str
            sample:
                - "foo.bar@example.com"
        id:
            description: The Team email address
            returned: always
            type: int
            sample:
                - 42
        memberCount:
            description: The number of Team members
            returned: always
            type: int
            sample:
                - 42
        name:
            description: The name of the team.
            returned: always
            type: str
            sample:
                - "grafana_working_group"
        members:
            description: The list of Team members
            returned: always
            type: list
            sample:
                - ["john.doe@exemple.com"]
        orgId:
            description: The organization id that the team is part of.
            returned: always
            type: int
            sample:
                - 1
'''

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url

__metaclass__ = type


class AzureActiveDirectoryInterface(object):

    ms_graph_api_url = "https://xxx.microsoft.com"

    def __init__(self, module):
        self._module = module
        self.headers = {"Content-Type": "application/json"}
        self.session_token = self._get_token()

    def _send_request(self, url, data=None, headers=None, method="GET"):
        if data is not None:
            data = json.dumps(data, sort_keys=True)
        if not headers:
            headers = []

        full_url = "{ms_graph_api_url}{path}".format(ms_graph_api_url=self.ms_graph_api_url, path=url)
        resp, info = fetch_url(self._module, full_url, data=data, headers=headers, method=method)
        status_code = info["status"]
        if status_code == 404:
            return None
        elif status_code == 401:
            self._module.fail_json(failed=True, msg="Unauthorized to perform action '%s' on '%s'" % (method, full_url))
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code == 200:
            return self._module.from_json(resp.read())
        self._module.fail_json(failed=True, msg="Grafana Teams API answered with HTTP %d" % status_code)

    def _get_token(self):
        pass

    def create_group(self, name):
        url = "/api/groups"
        group = dict(name=name)
        response = self._send_request(url, data=group, headers=self.headers, method="POST")
        return response

    def get_group(self, name):
        url = "/api/teams/search?name={team}".format(team=name)
        response = self._send_request(url, headers=self.headers, method="GET")
        if not response.get("totalCount") <= 1:
            raise AssertionError("Expected 1 team, got %d" % response["totalCount"])

        if len(response.get("teams")) == 0:
            return None
        return response.get("teams")[0]

    def update_group(self, group_id):
        url = "/api/teams/{team_id}".format(team_id=team_id)
        team = dict(email=email, name=name)
        response = self._send_request(url, data=team, headers=self.headers, method="PUT")
        return response

    def delete_group(self, group_id):
        url = "/api/teams/{team_id}".format(team_id=team_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response


def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )
    return module


argument_spec = url_argument_spec()
argument_spec.update(
    name=dict(type='str', required=True),
)


def main():

    module = setup_module_object()
    state = module.params['state']
    name = module.params['name']

    grafana_iface = GrafanaTeamInterface(module)

    changed = False
    if state == 'present':
        team = grafana_iface.get_team(name)
        if team is None:
            new_team = grafana_iface.create_team(name, email)
            team = grafana_iface.get_team(name)
            changed = True
        if members is not None:
            cur_members = grafana_iface.get_team_members(team.get("id"))
            plan = diff_members(members, cur_members)
            for member in plan.get("to_add"):
                grafana_iface.add_team_member(team.get("id"), member)
                changed = True
            if enforce_members:
                for member in plan.get("to_del"):
                    grafana_iface.delete_team_member(team.get("id"), member)
                    changed = True
            team = grafana_iface.get_team(name)
        team['members'] = grafana_iface.get_team_members(team.get("id"))
        module.exit_json(failed=False, changed=changed, team=team)
    elif state == 'absent':
        team = grafana_iface.get_team(name)
        if team is None:
            module.exit_json(failed=False, changed=False, message="No team found")
        result = grafana_iface.delete_team(team.get("id"))
        module.exit_json(failed=False, changed=True, message=result.get("message"))


def diff_members(target, current):
    diff = {"to_del": [], "to_add": []}
    for member in target:
        if member not in current:
            diff["to_add"].append(member)
    for member in current:
        if member not in target:
            diff["to_del"].append(member)
    return diff


if __name__ == '__main__':
    main()
