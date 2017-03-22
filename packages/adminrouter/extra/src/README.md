# Admin Router
The Admin Router is an open-source Nginx configuration created by Mesosphere
that provides central authentication and proxy to DCOS services within the cluster.

<img src="admin-router.png" alt="" width="100%" align="middle">

This repository is intended as just an overlay on top of OpenSource repository.
It provides Enterprise-specific features and behaviour used in Enterprice
DC/OS.

## Ports
<img src="admin-router-table.png" alt="" width="100%" align="middle">

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
