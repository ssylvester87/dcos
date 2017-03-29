# Admin Router
The Admin Router is an open-source Nginx configuration created by Mesosphere
that provides central authentication and proxy to DCOS services within the cluster.

This repository is intended as just an overlay on top of OpenSource repository.
It provides Enterprise-specific features and behaviour used in Enterprice
DC/OS.

## Upstream documentation
Non-EE topics are covered in Open Admin Router documentation. It resides in
Open DC/OS repository: https://github.com/dcos/dcos/tree/master/packages/adminrouter/extra/src

## Applying overlay
This repository on its own is incomplete and it needs to be applied on top of
Open Admin Router repository in order to be usefull. This can be achieved by:

```
echo <path to your local checkout of Open DC/OS> > .dcos-open.path
make apply-open
```

## Authorization and authentication

Authn and authz in EE build on top of Open Source code. The authentication
process is the same in EE and has been described in Open Admin Router
documentation. The only difference is that EE uses `RS256` tokens.

The authorization process on the other hand is much more sophisticated - there
is a fine-grained authorization basing on resource IDs. Open Admin Router is
permitting only for all-or-nothing kind of authorization. On top of that all
authn/autz decisions done Admin Router are audit-logged.

### Authorization

The authz decision is made by the IAM itself, Admin Router's task is to perform
authn, extract `uid` claim from JWT and issue a query to IAM with access
control entry data.

The access control data is a triple consisting of:
* subject: `uid` claim from the token
* resource ID: the name of the ACL that we are checking access for
* action to be taken on the resource: currently AR queries only for `full`
  action for all resources.

The communication with IAM is done using REST API, and the result is a JSON
document stating whether subject's is authorized to perform requested action.

Basing on IAM response, AR either permits the request or responds with 403 to
the client.

### Locations that do require only authn

Some of the services running on DC/OS do not rely on Admin Router to provide
authz and instead implement their own authorizers (e.g. secrets service). Other
may want to permit all authenticated users by default. In this cases AR
performs only authn using `do_authn_or_exit()` LUA function. If the request
contains a valid token, it is permitted.

### Parameter-less interface

As mentioned in Open Source AR documentation, to keep code DRY there
has to be a way to have the same location block configuration on Nginx
configuration level and different code/function call parameters on LUA code
level depending on the repository flavour.

In case of EE code it is all about resource names that should be passed to the
LUA code. They are hardcoded into the functions that are exposed by LUA code
and passed to more generic functions that are also exposed by the auth module.

This way Nginx configuration can use the same function name even though
internally the code does different things.


### Audit logging

All decisions made by EE Admin Router are logged into the AR log for later
inspection. The information that is being logged is:
* log entry type: always `audit`
* entry timestamp
* authorizer that made the authn/authz decision: always `adminrouter`
* ID of the resource which is being accessed
* action with which the resource is being accessed
* the decision that was made by Admin Router authorizer, along with the reason
  for that decision
* source IP and port
* request URI
