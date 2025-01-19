To make `podman compose` working at Ubuntu 24.04 LTS, the default compose provider has to be set in the `containers.conf` file.

Create `~/.config/containers/containers.conf` if not exists and add (or edit) the `engine` section:

```
[engine]
compose_providers=["/usr/bin/podman-compose"]
```

Run `podman compose` to check it works. It should execute `/usr/bin/podman-compose` instead of `/usr/bin/docker-compose`.
