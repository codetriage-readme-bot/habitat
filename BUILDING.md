# Setting up the environment

## Officially supported environment: Ubuntu Latest (17.10/Artful)

([Other environments](#Unsupported-environments) work, but are not officially supported)

You can run this environment natively or in VM. [ISOs for both server and desktop versions are available here](http://releases.ubuntu.com/17.10/).
This installation method uses as many packages from Ubuntu as possible.
If you don't have it, you'll first need to install `git`:
```
sudo -E apt-get install -y --no-install-recommends git
```

Then, clone the codebase and enter the directory:

```
git clone https://github.com/habitat-sh/habitat.git
cd habitat
```

Then, run the system preparation scripts

```
cp components/hab/install.sh /tmp/
sh support/linux/install_dev_0_ubuntu_latest.sh
sh support/linux/install_dev_9_linux.sh
```

Ubuntu-Server 17.10 has an issue that prevents update from working because it
tries to read from a CD-ROM that's almost certainly not there. If you get an
error like this:
```
E: The repository 'cdrom://Ubuntu-Server 17.10 _Artful Aardvark_ - Release amd64 (20171017.1) artful Release' does not have a Release file.
N: Updating from such a repository can't be done securely, and is therefore disabled by default.
N: See apt-secure(8) manpage for repository creation and user configuration details.
```
You can run this command to comment out the problematic line in the sources list:
```
sudo sed -i.bak '/deb cdrom/s/^/#/g' /etc/apt/sources.list
```

Then, make sure rust's `cargo` command is working. You'll need to add `$HOME/.cargo/bin` to your `$PATH`.
On shells that use `.profile`, you can run
```
source ~/.profile
```
For other shells see the documentation for modifying the executable path. For `fish`, you can run
```
set -U fish_user_paths $fish_user_paths "$HOME/.cargo/bin"
```
Check that `cargo` is correctly installed by running
```
cargo --version
```

# Compiling habitat binaries

In the root of the `habitat` repo:
```
make
```

The binaries will be in `habitat/target/debug` and can be run directly, or you can use `cargo` commands in the various `components` subdirectories. For example:
```
cd components/sup
cargo run -- --help
cargo run -- status
```

# Testing changes

The `hab` command execs various other binaries such as `hab-sup`. By default, this will run the latest installed habitat package version of the binary. To use your development version, this behavior can be overridden with the following environment variables:
* HAB_BUTTERFLY_BINARY
* HAB_DOCKER_BINARY
* HAB_LAUNCH_BINARY
* HAB_STUDIO_BINARY
* HAB_SUP_BINARY

For example, to run your newly-compiled version of `hab-sup` set `HAB_SUP_BINARY` to `/path/to/habitat/target/debug/hab-sup`. This can be done either through exporting (syntax differs, check your shell documentation):
```
export HAB_SUP_BINARY=/path/to/habitat/target/debug/hab-sup
```
or setting the value upon execution of the `hab` binary:
```
env HAB_SUP_BINARY=/path/to/habitat/target/debug/hab-sup hab sup status
```

# Unsupported environments

## Mac OS X for Linux Development

These install instructions assume you want to develop, build, and run the
various Habitat software components in a Linux environment. The Habitat core
team suggests that you use our consistent development environment that we call
the "devshell" as the easiest way to get started.

1. [Install Docker for Mac](https://www.docker.com/products/docker)
1. Checkout the source by running `git clone git@github.com:habitat-sh/habitat.git; cd habitat`
1. Run `make` to compile all Rust software components (this will take a while)
1. (Optional) Run `make test` if you want to run the tests. This will take a while.

Everything should come up green. Congratulations - you have a working Habitat
development environment.

You can enter a devshell by running `make shell`. This will drop you in a
Docker container at a Bash shell. The source code is mounted in under `/src`,
meaning you can use common Rust workflows such as `cd components/sup; cargo
build`.

**Note:** The Makefile targets are documented. Run `make help` to show the
output (this target requires `perl`).

**Optional:** This project compiles and runs inside Docker containers so while
installing the Rust language isn't strictly necessary, you might want a local
copy of Rust on your workstation (some editors' language support require an
installed version). To [install stable
Rust](https://www.rust-lang.org/install.html), run: `curl -sSf
https://sh.rustup.rs | sh`. Additionally, the project maintainers use
[rustfmt](https://github.com/rust-lang-nursery/rustfmt) for code formatting. If
you are submitting changes, please ensure that your work has been run through
the latest version of rustfmt. An easy way to install it (assuming you have
Rust installed as above), is to run `cargo install rustfmt` and adding
`$HOME/.cargo/bin` to your `PATH`.

**Note2:** While this Docker container will work well for getting started with Habitat development, [you may want to consider using a VM](#vm-vs-docker-development) as you start compiling Habitat components.  To do this, create a VM with your preferred flavor of Linux and follow the appropriate instructions for that flavor below.


## Mac OS X for Native Development

These instructions assume you want to develop, build, and run the various
Habitat software components in a macOS environment. Components other than
the `hab` CLI itself aren't all supported on Mac, but it is sometimes useful
to run parts of the Habitat ecosystem without virtualization. We recommend
using another environment.

First clone the codebase and enter the directory:

```
git clone https://github.com/habitat-sh/habitat.git
cd habitat
```

Then, run the system preparation scripts and try to compile the project:

```
cp components/hab/install.sh /tmp/
sh support/mac/install_dev_0_mac_latest.sh
sh support/mac/install_dev_9_mac.sh
. ~/.profile
export PKG_CONFIG_PATH="/usr/local/opt/libarchive/lib/pkgconfig:/usr/local/opt/openssl/lib/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"
export IN_DOCKER=false
make
```

For the builds to find the libarchive and openssl libraries, you will need to
set the `PKG_CONFIG_PATH` environment variable as above before running `cargo
build`, `cargo test`, etc. Additionally to use the Makefile on Mac and not have
the tasks execute in the Docker-based devshell (see above), you will need to
set `IN_DOCKER=false` in your environment. If you use an environment switcher
such as [direnv](https://direnv.net/), you can set up the following in the root
of the git repository:

```
echo 'export PKG_CONFIG_PATH="/usr/local/opt/libarchive/lib/pkgconfig:/usr/local/opt/openssl/lib/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"' > .envrc
direnv allow
```

## Ubuntu: 14.04+ (Trusty+)

This can be used to build and install on older versions of Ubuntu where
libsodium and czmq aren't available.

First clone the codebase and enter the directory:

```
git clone https://github.com/habitat-sh/habitat.git
cd habitat
```

Then, run the system preparation scripts and try to compile the project:

```
cp components/hab/install.sh /tmp/
sh support/linux/install_dev_0_ubuntu_14.04.sh
sh support/linux/install_dev_9_linux.sh
. ~/.profile
make
```

These docs were tested with a Docker image, created as follows:

```
docker run --rm -it ubuntu:trusty bash
apt-get update && apt-get install -y sudo git-core
useradd -m -s /bin/bash -G sudo jdoe
echo jdoe:1234 | chpasswd
sudo su - jdoe
```


## Centos 7

First clone the codebase and enter the directory:

```
git clone https://github.com/habitat-sh/habitat.git
cd habitat
```

Then, run the system preparation scripts and try to compile the project:

```
cp components/hab/install.sh /tmp/
sh support/linux/install_dev_0_centos_7.sh
sh support/linux/install_dev_9_linux.sh
. ~/.profile
make
```

If you have issues with libsodium at runtime, ensure that you've set
`LD_LIBRARY_PATH` and `PKG_CONFIG_PATH`:

    export LD_LIBRARY_PATH=/usr/local/lib
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

These docs were tested with a Docker image, created as follows:

```
docker run --rm -it centos:7 bash
yum install -y sudo git
useradd -m -s /bin/bash -G wheel jdoe
echo jdoe:1234 | chpasswd
sudo su - jdoe
```


## Arch Linux

First clone the codebase and enter the directory:

```
git clone https://github.com/habitat-sh/habitat.git
cd habitat
```

Then, run the system preparation scripts and try to compile the project:

```
cp components/hab/install.sh /tmp/
sh support/linux/install_dev_0_arch.sh
sh support/linux/install_dev_9_linux.sh
. ~/.profile
make
```

These docs were tested with a Docker image, created as follows:

```
docker run --rm -it greyltc/archlinux bash
pacman -Syy --noconfirm
pacman -S --noconfirm sudo git
echo "%wheel ALL=(ALL) ALL" > /etc/sudoers.d/01_wheel
useradd -m -s /bin/bash -G wheel jdoe
echo jdoe:1234 | chpasswd
sudo su - jdoe
```

## VM vs. Docker development

While the available docker images can provide a convenient contributor onboarding experience, they may not prove ideal for extensive habitat development. Building habitat components is a disk intensive operation. Mounted file systems across network boundaries, even when confined to a single local host, can yield build times dramatically slower than building against a locally attached file system. Build times will be best on either a bare metal linux environment or a dedicated linux vm. Also note that when using vagrant to provision a vm for habitat development, it is advised that you do not put your habitat repo on a synced folder or at least do not use that folder as your build target.

The following directions clone the habitat repository into a local directory to realize faster build times; **however**, while faster, this approach carries the risk of losing your work if your VM should crash or get into an unrecoverable state. If developing in a VM, intermittently pushing a WIP to your Habitat fork can protect your progress.

In the root of the project is a Vagrantfile that provisions an Ubuntu environment for Habitat development:

```
vagrant up --provider virtualbox  # See the Vagrantfile for additional providers and boxes
```

Feel free to use this file as a jumping-off point for customizing your own Habitat development environment.

```
vagrant ssh
sudo su -
git clone https://github.com/habitat-sh/habitat.git
cd habitat/components/builder-api
cargo test
```

## Windows

These instructions are based on Windows 10 1607 (Anniversary update) or newer.
Most of it will probably work downlevel.

All commands are in PowerShell unless otherwise stated.  It is assumed that you
have `git` installed and configured.  Posh-Git is a handy PowerShell module for
making `git` better in your PowerShell console (`install-module posh-git`).

```
# Clone the Habitat source
git clone https://github.com/habitat-sh/habitat.git

cd habitat
./build.ps1 components/hab -configure
```
