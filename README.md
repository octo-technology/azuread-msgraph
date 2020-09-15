# Azure Active Directory Collection for Ansible

This repo hosts the `octo.azuread` Ansible Collection.
The collection includes a variety of Ansible content to help automate the management of Active Directory resources through the **Microsft Graph API**.



## Included content

Click on the name of a plugin or module to view that content's documentation:

  - **Connection Plugins**:
  - **Filter Plugins**:
  - **Inventory Source**:
  - **Callback Plugins**:
  - **Lookup Plugins**:
  - **Modules**:
    - azuread_group


## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the AzureAD collection, you need to install it with the Ansible Galaxy CLI:

    ansible-galaxy collection install octo.azuread

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: octo.azuread
    version: v0.1.0
```

### Using modules from the AzureAD Collection in your playbooks

You can either call modules by their Fully Qualified Collection Namespace (FQCN), like `octo.azuread.azuread_group`, or you can call modules by their short name if you list the `octo.azuread` collection in the playbook's `collections`, like so:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  collections:
    - octo.azuread

  tasks:
    - name: Create a group with a owner
      azuread_group:
        name: "{{ azuread_group.name }}"
        description: "{{ azuread_group.description }}"
        mail_nickname: "{{ azuread_group.mail_nickname }}"
        owners:
        - "https://graph.microsoft.com/v1.0/users/a802c037-468d-4dca-a21d-f60965f62313"
        state: "present"
        client_id: "{{ client_id }}"
        client_secret: "{{ client_secret }}"
        tenant_id: "{{ tenant_id }}"
```

For documentation on how to use individual modules and other content included in this collection, please see the links in the 'Included content' section earlier in this README.

## Testing and Development

If you want to develop new content for this collection or improve what's already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

### Testing with `ansible-test`

The `tests` directory contains configuration for running sanity and integration tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

You can run the collection's test suites with the commands:

    ansible-test sanity --docker -v --color
    ansible-test integration --docker -v --color

## Publishing New Versions

The current process for publishing new versions of the Collection is manual, and outside Ansible Galaxy.

  1. Ensure `CHANGELOG.md` contains all the latest changes.
  2. Update `galaxy.yml` and this README's `requirements.yml` example with the new `version` for the collection.
  3. Tag the version in Git and push to GitHub.
  4. Run the following commands to build and release the new version on Galaxy:

     ```
     ansible-galaxy collection build
     ```

Upload the archive as an artifact of the github release.

## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

## Contributing

Any contribution is welcome and we only ask contributors to:
* Provide *at least* integration tests for any contribution.
* Create an issues for any significant contribution that would change a large portion of the code base.
