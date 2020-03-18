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

from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url,url_argument_spec

__metaclass__ = type


class AzureActiveDirectoryInterface(object):
    ms_graph_api_url = "https://graph.microsoft.com/v1.0"

    def __init__(self, module):
        self._module = module
        token = self._get_token()
        self.headers = {"Content-Type": "application/json", "Authorization": "Bearer %s" % token.get("access_token")}

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
        client_id = "01ff3f2f-c91c-4db8-abdc-2ea5bfcd57f9"
        client_secret = "FIX_ME"
        scope = ["https://graph.microsoft.com/.default"]
        token_url = "https://login.microsoftonline.com/fe8041b2-2127-4652-9311-b420e55fd10e/oauth2/v2.0/token"

        client = BackendApplicationClient(client_id=client_id)
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(token_url=token_url,
                                  client_id=client_id,
                                  client_secret=client_secret,
                                  scope=scope)
        return token

    def create_group(self, name):
        url = "/groups"
        group = dict(name=name)
        response = self._send_request(url, data=group, headers=self.headers, method="POST")
        return response

    def get_directory_objects(self):
        url = "/directoryObjects/fe8041b2-2127-4652-9311-b420e55fd10e"
        response = self._send_request(url, headers=self.headers, method="GET")
        return response.get("value")

    def get_groups(self):
        #url = "/directoryObjects"
        url = "/groups"
        response = self._send_request(url, headers=self.headers, method="GET")
        return response.get("value")

    def get_group(self, name):
        groups = self.get_groups()
        for group in groups:
            if group.get("displayName") == name:
                return group

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
    state=dict(type='str', required=True)
)


def main():
    module = setup_module_object()
    state = module.params['state']
    name = module.params['name']

    azuread_iface  = AzureActiveDirectoryInterface(module)
#    res = azuread_iface.get_directory_objects()
#    raise Exception(res)

    changed = False
    if state == 'present':
        group = azuread_iface.get_group(name)
        if group is None:
            pass
            #new_team = grafana_iface.create_team(name, email)
            #team = grafana_iface.get_team(name)
            changed = True
        module.exit_json(changed=changed, group=group)
    elif state == 'absent':
        team = grafana_iface.get_team(name)
        if team is None:
            module.exit_json(failed=False, changed=False, message="No team found")
        result = grafana_iface.delete_team(team.get("id"))
        module.exit_json(failed=False, changed=True, message=result.get("message"))


if __name__ == '__main__':
    main()
