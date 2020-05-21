# Secrets

## Purge secret

Purge secret is being used to clean un-used Azure resources.
To create ServicePrincipal for this:

```
az ad sp create-for-rbac --name aro-rhdev-purge > aro-rhdev-purge.json
```

Grant newly created SP same access as Engineers on the team:

```
# Get objectID
az ad sp show --id $(cat aro-rhdev-purge.json | jq -r .appId) | jq .objectId
# Add ServicePrincipal to the Group
az ad group member add -g "ARO v4 RP Engineering" --member-id "OBJECT_ID"
```

```
export AZURE_CLIENT_ID=$(cat aro-rhdev-purge.json | jq -r '.appId')
export AZURE_CLIENT_SECRET=$(cat aro-rhdev-purge.json | jq -r '.password')
export AZURE_TENANT_ID=$(cat aro-rhdev-purge.json | jq -r '.tenant')
```
