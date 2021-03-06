#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, OCTO TECHNOLOGY
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'metadata_version': '1.1'
}

DOCUMENTATION = '''
---
module: azuread_group
author:
  - Rémi REY (@rrey)
  - Roberto Duarte (@DuarteRoberto)
short_description: Manage azure ad groups
description:
  - Create/update/delete AzureAD Groups through the Microsoft Graph API.
options:
  state:
    description:
      - The desired state for the group
    required: true
    type: str
    choices: ["present", "absent"]
  client_id:
    description:
      - the client id.
    required: true
    type: str
  client_secret:
    description:
      - the client secret.
    required: true
    type: str
  tenant_id:
    description:
      - id of the azure tenant.
    required: true
    type: str
  display_name:
    description:
      - The display name for the group.
    required: true
    aliases:
      - name
    type: str
  description:
    description:
      - An optional description for the group.
    required: true
    type: str
  group_types:
    description:
      - Specifies the group type and its membership.
    default: []
    required: false
    type: list
    elements: str
    choices: ["Unified","DynamicMembership"]
  mail_enabled:
    description:
      - Specifies whether the group is mail-enabled.
    default: false
    type: bool
  mail_nickname:
    description:
      - he mail alias for the group, unique in the organization.
    required: true
    type: str
  security_enabled:
    description:
      - Specifies whether the group is a security group.
    default: true
    type: bool
  owners:
    description:
      - This property represents the list of group owners.
      - The list can contain users or servicePrincipal. Example
      - "https://graph.microsoft.com/v1.0/users/<User_object_id>"
      - "https://graph.microsoft.com/v1.0/servicePrincipals/<sp_object_id>"
    required: true
    type: list
    elements: str
  enforce_owners:
    description:
      - Enforce the list of owners provided in C(owners) by removing owners
      - not in the list and adding missing ones.
    required: false
    type: bool
  members:
    description:
      - This property represents the list of group members (users or/and groups).
      - Since it can be groups and users, this is a list of directoryObject.
      - A member should be specified in a list and should have this form...
      - "https://graph.microsoft.com/v1.0/directoryObject/idOfMember"
    default: []
    type: list
    elements: str
  enforce_members:
    description:
      - Enforce the list of members provided in C(members) by removing members
      - not in the list and adding missing ones.
    required: false
    type: bool
extends_documentation_fragment:
- url
'''

EXAMPLES = '''
---
- name: create group in aad
  azuread_group:
    desired_name: "{{ azuread_group.name }}"
    description: "{{ azuread_group.description }}"
    mail_nickname: "{{ azuread_group.mail_nickname }}"
    state: "present"
    client_id: "{{ client_id }}"
    client_secret: "{{ client_secret }}"
    tenant_id: "{{ tenant_id }}"

- name: delete group in aad
  azuread_group:
    desired_name: "{{ azuread_group.name }}"
    description: "{{ azuread_group.description }}"
    mail_nickname: "{{ azuread_group.mail_nickname }}"
    client_id: "{{ client_id }}"
    client_secret: "{{ client_secret }}"
    tenant_id: "{{ tenant_id }}"
    state: absent
'''

RETURN = '''
---
team:
    description: Information about the Team
    returned: On success
    type: complex
    contains:
        context:
            description: Object context
            returned: always
            type: str
            sample:
                - "https://graph.microsoft.com/v1.0/$metadata#groups/$entity"
        id:
            description: The unique identifier for the group.
            returned: always
            type: str
            sample:
                - "502df398-d59c-469d-944f-34a50e60db3f"
        deletedDateTime:
            description:
                - For some Azure Active Directory objects (user, group, application), if the object is deleted,
                - it is first logically deleted, and this property is updated with the date and time when the object
                - was deleted. Otherwise this property is null. If the object is restored,
                - this property is updated to null.
            returned: always
            type: str
            sample:
                - null
        classification:
            description: Describes a classification for the group (such as low, medium or high business impact).
            returned: always
            type: str
            sample:
                - null
        createdDateTime:
            description:
                - Timestamp of when the group was created.
                - The value cannot be modified and is automatically populated when the group is created.
                - The Timestamp type represents date and time using ISO 8601 format and is always in UTC time.
            returned: always
            type: str
            sample:
                - "2018-12-27T22:17:07Z"
        creationOptions:
            description: ???
            returned: always
            type: list
            sample:
                - []
        description:
            description: An optional description for the group.
            returned: always
            type: str
            sample:
                - "This is a random description of the group"
        displayName:
            description:
                - The display name for the group.
                - This property is required when a group is created and cannot be cleared during updates.
            returned: always
            type: str
            sample:
                - "Operations group"
        groupTypes:
            description: Specifies the group type and its membership.
            returned: always
            type: list
            sample:
                - ["Unified"]
        mail:
            description: The SMTP address for the group.
            returned: always
            type: str
            sample:
                - "operations2019@contoso.com"
        mailEnabled:
            description: Specifies whether the group is mail-enabled.
            returned: always
            type: bool
            sample:
                - true
        mailNickname:
            description:
                - The mail alias for the group, unique in the organization.
                - This property must be specified when a group is created.
            returned: always
            type: str
            sample:
                - "operations2019"
        onPremisesLastSyncDateTime:
            description: Indicates the last time at which the group was synced with the on-premises directory.
            returned: always
            type: str
            sample:
                - null
        onPremisesSecurityIdentifier:
            description:
                - Contains the on-premises security identifier (SID) for the group that was synchronized
                - from on-premises to the cloud.
            returned: always
            type: str
            sample:
                - null
        onPremisesSyncEnabled:
            description:
                - true if this group is synced from an on-premises directory; false if this group was originally
                - synced from an on-premises directory but is no longer synced;
                - null if this object has never been synced from an on-premises directory (default).
            returned: always
            type: str
            sample:
                - null
        preferredDataLocation:
            description: The preferred data location for the group.
            returned: always
            type: str
            sample:
                - "CAN"
        proxyAddresses:
            description: Email addresses for the group that direct to the same group mailbox.
            returned: always
            type: str
            sample:
                - ["SMTP:operations2019@contoso.com"]
        renewedDateTime:
            description:
                - Timestamp of when the group was last renewed.
                - This cannot be modified directly and is only updated via the renew service action.
            returned: always
            type: str
            sample:
                - "2018-12-27T22:17:07Z"
        resourceBehaviorOptions:
            description: ???
            returned: always
            type: list
            sample:
                - []
        resourceProvisioningOptions:
            description: ???
            returned: always
            type: list
            sample:
                - []
        securityEnabled:
            description: securityEnabled
            returned: always
            type: bool
            sample:
                - false
        visibility:
            description: Specifies the visibility of an Office 365 group.
            returned: always
            type: str
            sample:
                - "Public"
        onPremisesProvisioningErrors:
            description: Errors when using Microsoft synchronization product during provisioning.
            returned: always
            type: list
            sample:
                - []
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec
from ansible.module_utils.common.dict_transformations import snake_dict_to_camel_dict

try:
    from requests_oauthlib import OAuth2Session
    from oauthlib.oauth2 import BackendApplicationClient

    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

__metaclass__ = type


OBJECT_TYPE_MAP = {
    '#microsoft.graph.user': "graph.microsoft.com/v1.0/users",
    '#microsoft.graph.servicePrincipal': "graph.microsoft.com/v1.0/servicePrincipals"
}


class AzureActiveDirectoryInterface(object):
    ms_graph_api_url = "https://graph.microsoft.com"

    def __init__(self, module):
        self._module = module
        token = self._get_token()
        self.headers = {"Content-Type": "application/json", "Authorization": "Bearer %s" % token.get("access_token")}

    def _send_request(self, url, data=None, headers=None, method="GET", api_version="v1.0"):
        if data is not None:
            data = json.dumps(data, sort_keys=True)
        if not headers:
            headers = []

        full_url = "{ms_graph_api_url}/{version}/{path}".format(ms_graph_api_url=self.ms_graph_api_url,
                                                                version=api_version, path=url)
        resp, info = fetch_url(self._module, full_url, data=data, headers=headers, method=method)
        status_code = info["status"]
        if status_code == 404:
            return None
        elif status_code == 400:
            self._module.fail_json(msg=json.loads(info["body"]).get("error"))
        elif status_code == 401:
            self._module.fail_json(msg="Unauthorized to perform action '%s' on '%s'" % (method, full_url))
        elif status_code == 403:
            self._module.fail_json(msg="Permission Denied")
        elif 200 <= status_code < 299:
            body = resp.read()
            if body:
                return self._module.from_json(body)
            return
        self._module.fail_json(failed=True, msg="Microsoft Graph API answered with HTTP %d" % status_code)

    def _get_token(self):
        client_id = self._module.params.get("client_id")
        client_secret = self._module.params.get("client_secret")
        scope = ["https://graph.microsoft.com/.default"]
        token_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token".format(
            tenant_id=self._module.params.get("tenant_id"))

        client = BackendApplicationClient(client_id=client_id)
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(token_url=token_url,
                                  client_id=client_id,
                                  client_secret=client_secret,
                                  scope=scope)
        return token

    def create_group(self, group):
        url = "/groups"
        owners = group.pop("owners")
        if group.get("members") is not None:
            members = group.pop("members")
            group["members@odata.bind"] = members
        group["owners@odata.bind"] = owners
        response = self._send_request(url, data=group, headers=self.headers, method="POST")
        return response

    def get_group(self, name):
        url = "/groups?$filter=startswith(displayName,'%s')" % name
        response = self._send_request(url, headers=self.headers, method="GET")
        groups = response.get("value")
        if len(groups) > 1:
            self.module.fail_json(msg="Expected 1 group matching query, found %d" % len(groups))
        elif len(groups) == 0:
            return None
        return groups[0]

    def update_group(self, group_id, group):
        url = "/groups/{group_id}".format(group_id=group_id)
        self._send_request(url, data=group, headers=self.headers, method="PATCH")

    def delete_group(self, group_id):
        url = "/groups/{group_id}".format(group_id=group_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response

    def converge_owners(self, group_id, current, new, enforce):
        changed = False
        for owner in new:
            if owner not in current:
                changed = True
                self.add_owner(group_id, owner)
        if enforce:
            for owner in current:
                if owner not in new:
                    changed = True
                    self.remove_owner(group_id, owner)
        return changed

    def get_owners(self, group_id):
        url = "/groups/{group_id}/owners".format(group_id=group_id)
        response = self._send_request(url, headers=self.headers, method="GET",
                                      api_version="beta")
        return response.get("value")

    def get_owners_id(self, group_id):
        owners = self.get_owners(group_id)
        owners_id = []
        for owner in owners:
            obj_type = owner.get('@odata.type')
            obj_uri = OBJECT_TYPE_MAP.get(obj_type)
            owner_url = "https://{uri}/{obj_id}".format(uri=obj_uri, obj_id=owner.get('id'))
            owners_id.append(owner_url)
        return owners_id

    def add_owner(self, group_id, owner):
        url = "/groups/{group_id}/owners/$ref".format(group_id=group_id)
        data = {"@odata.id": owner}
        response = self._send_request(url, data=data, headers=self.headers, method="POST")
        return response

    def remove_owner(self, group_id, owner):
        owner_id = owner.split("/")[-1]
        url = "/groups/{group_id}/owners/{owner_id}/$ref".format(group_id=group_id, owner_id=owner_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response

    def converge_members(self, group_id, current, new, enforce):
        changed = False
        for member in new:
            if member not in current:
                changed = True
                self.add_member(group_id, member)
        if enforce:
            for member in current:
                if member not in new:
                    changed = True
                    self.remove_member(group_id, member)
        return changed

    def get_members(self, group_id):
        url = "/groups/{group_id}/members".format(group_id=group_id)
        response = self._send_request(url, headers=self.headers, method="GET")
        return response.get("value")

    def get_members_id(self, group_id):
        members = self.get_members(group_id)
        # not users but directoryObjects because members can also be groups
        members_id = ["https://graph.microsoft.com/v1.0/directoryObjects/" + member.get('id') for member in members]
        return members_id

    def add_member(self, group_id, member):
        url = "/groups/{group_id}/members/$ref".format(group_id=group_id)
        data = {"@odata.id": member}
        response = self._send_request(url, data=data, headers=self.headers, method="POST")
        return response

    def remove_member(self, group_id, member):
        member_id = member.split("/")[-1]
        url = "/groups/{group_id}/members/{member_id}/$ref".format(group_id=group_id, member_id=member_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response


def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )
    return module


def build_group_from_params(params):
    GROUP_PARAMS = ["display_name", "description", "group_types", "mail_enabled",
                    "mail_nickname", "security_enabled", "owners", "members"]
    group = {}
    for param in GROUP_PARAMS:
        group[param] = params[param]
    if group["members"] == []:
        group.pop("members")
    return snake_dict_to_camel_dict(group)


argument_spec = url_argument_spec()
argument_spec.update(
    state=dict(type='str', required=True, choices=["present", "absent"]),
    client_id=dict(type='str', required=True),
    client_secret=dict(type='str', required=True, no_log=True),
    tenant_id=dict(type='str', required=True),
    display_name=dict(type='str', required=True, aliases=["name"]),
    description=dict(type='str', required=True),
    group_types=dict(type='list', elements='str', default=[], choices=["Unified", "DynamicMembership"]),
    mail_enabled=dict(type='bool', default=False),
    mail_nickname=dict(type='str', required=True),
    security_enabled=dict(type='bool', default=True),
    owners=dict(type='list', elements='str', required=True),
    enforce_owners=dict(type='bool', required=False, default=False),
    members=dict(type='list', elements='str', default=[]),
    enforce_members=dict(type='bool', required=False, default=False)
)


def compare_groups(current, new):
    current_keys = current.keys()
    new_keys = new.keys()
    current_keys_to_remove = [item for item in current_keys if item not in new_keys]
    new_keys_to_remove = ["owners", "members"]
    # Remove the unknown keys from remote group
    for item in current_keys_to_remove:
        if item in current:
            current.pop(item)
    # Remove the keys that are not returned by Get method from new group
    for item in new_keys_to_remove:
        if item in new:
            new.pop(item)
    if current != new:
        return dict(before=current, after=new)


def main():
    module = setup_module_object()

    if not HAS_DEPS:
        module.fail_json(msg="module requires requests and requests-oauthlib")

    state = module.params['state']
    name = module.params['display_name']
    owners = module.params['owners']
    enforce_owners = module.params['enforce_owners']

    members = module.params['members']
    enforce_members = module.params['enforce_members']

    azuread_iface = AzureActiveDirectoryInterface(module)
    group = azuread_iface.get_group(name)

    changed = False
    diff = None
    if state == 'present':
        new_group = build_group_from_params(module.params)
        if group is None:
            group = azuread_iface.create_group(new_group)
            changed = True
        else:

            diff = compare_groups(group.copy(), new_group.copy())
            if diff is not None:
                azuread_iface.update_group(group.get("id"), diff["after"])
                changed = True

            current_owners = azuread_iface.get_owners_id(group.get("id"))
            if current_owners != owners:
                owners_changed = azuread_iface.converge_owners(group.get("id"), current_owners, owners, enforce_owners)
                if owners_changed:
                    changed = True

            current_members = azuread_iface.get_members_id(group.get("id"))
            if current_members != members:
                members_changed = azuread_iface.converge_members(group.get("id"), current_members, members,
                                                                 enforce_members)
                if members_changed:
                    changed = True

        group = azuread_iface.get_group(name)
        group["owners"] = azuread_iface.get_owners(group.get("id"))
        group["members"] = azuread_iface.get_members(group.get("id"))
        module.exit_json(changed=changed, group=group, diff=diff)
    elif state == 'absent':
        if group is None:
            module.exit_json(failed=False, changed=False, message="No group found")
        azuread_iface.delete_group(group.get("id"))
        module.exit_json(failed=False, changed=True, message="Group deleted")


if __name__ == '__main__':
    main()
