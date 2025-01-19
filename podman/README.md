# Podman cheatsheet

## Running containers

```sh
# with logs
podman-compose up

# as daemon
podman-compose up -d
```

## Checking running images

```sh
podman ps -a
```

## Connecting to container

```sh
podman-compose exec <CONTAINER_NAME OR CONTAINER_HASH> bash
```

## Kill containers

```sh
podman-compose down

# remove volumes
podman-compose down -v
```

## Listing images

```sh
podman images -a
```

## Inspecting image

```sh
podman inspect <IMAGE_HASH>
```