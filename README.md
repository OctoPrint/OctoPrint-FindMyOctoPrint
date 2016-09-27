# Find My OctoPrint

Makes your OctoPrint instance discoverable via ``find.octoprint.org``.

## Setup

Install via the bundled [Plugin Manager](https://github.com/foosel/OctoPrint/wiki/Plugin:-Plugin-Manager)
or manually using this URL:

    https://github.com/OctoPrint/OctoPrint-FindMyOctoPrint/archive/master.zip

## Configuration

```
plugins:
  findmyoctoprint:
    # registry endpoint to use
    url: https://find.octoprint.org/registry

    # interval for re-registrations after a client has been seen
    interval_client: 300.0

    # interval for re-registrations when no client has been seen yet
    interval_noclient: 60.0

    # everything under "public" is taken from the discovery plugin
    # settings if possible but can be overwritten here too
    #
    # public:
    #   uuid: <unique id, auto generated on demand>
    #   scheme: <http or https>
    #   port: <external port to use for connections>
    #   path: <path prefix to reach octoprint>
    #   httpUser: <http user name if needed>
    #   httpPass: <http password if needed>
```
