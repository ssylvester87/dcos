## buildinfo.json

openresty package is hosted on downloads.mesosphere.io because the project
download location returns a 403 due to the python user-agent provided by
urllib. Hosting our own mirror of the package seems more reasonable than
changing the useragent for all downloads.
