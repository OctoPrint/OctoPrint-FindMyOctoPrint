# Find My OctoPrint

Makes your OctoPrint instance discoverable via [find.octoprint.org](http://find.octoprint.org).

## Setup

Install via the bundled [Plugin Manager](https://docs.octoprint.org/en/master/bundledplugins/pluginmanager.html)
or manually using this URL:

    https://github.com/OctoPrint/OctoPrint-FindMyOctoPrint/archive/main.zip

**Note:** Requires Python 3.7 or later!

## Configuration

``` yaml
plugins:
  findmyoctoprint:
    # registry endpoint to use, default is https://findd.octoprint.org (sic!)
    url: https://findd.octoprint.org/registry

    # interval for re-registrations after a client has been seen
    interval_client: 300.0

    # interval for re-registrations when no client has been seen yet
    interval_noclient: 60.0

    # instance name if server name is configured
    instance_with_name: "OctoPrint instance \"{name}\""

    # instance name if only the hostname is known
    instance_with_host: "OctoPrint on {host}"

    # paths whose existance will disable the updater
    #
    # can be used to easily disable even before very first startup
    # for privacy reasons
    # disable_if_exists:
    # - /boot/dont_register.txt

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
