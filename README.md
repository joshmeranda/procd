# Procd
Procd is a process monitoring daemon for linux, providing logging and policing functionality.

## Build
This project is built using GNU's make. To build use the default target:

```
make
```

This project is built using GNU's Compiler Collection (gcc) by default, to use a different C compiler specify the `CC`
value at compile time: `make CC=cc`

## Installation
To install utilize the `install` target along with the `INSTALL_DIR` and `SERVICE_INSTALL_DIR` to customize install
locations for the compiled binary and the systemd service file. Be careful to remember where you install this project
as you will need them to uninstall the project easily.

```
# install the project to user level directories rather than system level.
make install INSTALL_DIR=$HOME/.local/bin SERVICE_INSTALL_DIR=$HOME/.local/systemd/service

# use the same values to uninstall
make uninstall INSTALL_DIR=$HOME/.local/bin SERVICE_INSTALL_DIR=$HOME/.local/systemd/service
```

This will install a systemd unit and the binary into the specified locations, as well as a [default configuration](/examples/procd.conf)
to `/etc/procd.conf` which can be edited by the user to customized the service behavior.

## Running
Procd can be run as a standalone program operated via command line interface or as a systemd service. To run via
command line you will need admin privileges. For more detailed usage run `procd -h` for descriptions of available
arguments. Running as a service daemon is simple: `systemctl start procd`. When run as a service, all output is
redirected to journald.