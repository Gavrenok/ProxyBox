# ProxyBox — English guide

**English** | [Русский](README.ru.md)

A local Raspberry Pi gateway for phones and Macs: Wi-Fi → sing-box → your
selected proxy. The web panel runs on the Pi. This is an independent project;
the commercial GeoBox firmware is not included in the installation package.
The current panel and internal service names still use `GeoBox` / `geobox`.

**Status: preview.** The application runs on our Raspberry Pi 5. The new
installer has not completed a full clean-SD installation, reboot and phone
test. Use a separate card for an initial installation. Do not run `--install`
over an existing setup. The project's license has not yet been selected.

## Features

- Proxy import and library, per-device assignments and exit checks.
- Switching between compatible saved proxies without restarting the engine.
- Blocking direct client access when the tunnel is unavailable; traffic counters.
- IPv6 blocked by default, with a proxy mode enabled after checking support
  through the global proxy. Per-device assignments disable IPv6 for all clients.
- Browser IP/WebRTC diagnostics and a separate audit of the Pi's network rules.
- An on-demand “Why is there no internet?” report in Overview: proxy assignment,
  upstream route, Wi-Fi, tunnel, network policy, HTTPS and local DNS. It does not
  switch proxies or restart services. Results expire after five minutes or changes
  to configuration/client address. A timeout is not treated as proof of an expired proxy.
- Settings backup and Telegram notifications.
- Experimental location simulation for a paired iPhone: apply the proxy's
  coordinates, restore real location, and optionally synchronize automatically.

An IP address and a device's location are different things. A proxy connection
does not itself change the phone's GPS, language or time zone. Our iPhone
method requires Developer Mode and initial pairing. Wireless pairing, location
simulation and persistence after closing the control tunnel were verified on
an iPhone 16 Pro Max running iOS 27.0. Long sleep and reboot behavior have not
completed full testing. System location simulation for Mac is not implemented.

## Supported starting system

The current target is a Raspberry Pi 5 running 64-bit Raspberry Pi OS/Debian 13,
Python 3.13, NetworkManager and systemd. The upstream connection uses **eth0**;
the built-in **wlan0** is dedicated to the access point.

The installation reserves `10.77.0.0/24`, `fd77:6765:6f62:1::/64`, routing
table 100, the `geobox-ap` connection profile and the `sbtun` interface. Your
home network must not overlap `10.77.0.0/24`. Globally disabling IPv6 is not
supported: the local iPhone tunnel needs it, while client egress is filtered
separately.

Verified versions: sing-box **1.14.4** with Clash API support, and optional
iPhone runtime **pymobiledevice3 11.49.0**. These dependencies are not
automatically upgraded to newer versions.

## Prepare a clean SD card

In Raspberry Pi Imager, configure a user, SSH and a hostname such as `geobox`.
Connect Ethernet. Set your actual Wi-Fi country using `sudo raspi-config`.
The commands below are intended for a new dedicated system, not an existing
home router with configured DNS, DHCP or VPN services.

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-venv network-manager dnsmasq nftables iproute2 iw curl ca-certificates avahi-daemon avahi-utils rfkill
sudo systemctl stop dnsmasq
sudo nmcli radio wifi on
```

Add the official sing-box APT repository using the
[upstream instructions](https://sing-box.sagernet.org/installation/package-manager/).
Then install the exact verified version:

```sh
sudo apt-get update
sudo apt-get install sing-box=1.14.4
sudo apt-mark hold sing-box
sudo systemctl disable --now sing-box.service
sudo systemctl enable --now NetworkManager avahi-daemon
```

If that version is no longer available, stop: a different version requires
configuration compatibility checks. OS package preparation is separate from
the GeoBox installation transaction and is not rolled back by our installer.

## Build and install

On a computer with Git and Python:

```sh
git clone https://github.com/Gavrenok/ProxyBox.git
cd ProxyBox
python pi/build_release.py --output dist/geobox-preview.tar.gz
```

The archive contains only explicitly listed source files, service templates,
the installer, Russian and English guides, and a SHA256 manifest. It contains
no user configurations, pairing keys, research files or firmware images.
Identical source bytes produce an identical archive. The manifest checks
integrity; it does not authenticate the publisher.

Transfer the archive to the Pi. Extract it into a **new empty directory**:

```sh
mkdir geobox-preview
tar -xzf geobox-preview.tar.gz -C geobox-preview
cd geobox-preview
sudo python3 install.py --check
sudo python3 install.py --install --ssid 'My GeoBox'
```

Wi-Fi and panel passwords are requested with hidden input and are not passed
as command arguments. The default band is 2.4 GHz; add `--band a` for 5 GHz.
Channel availability depends on the country and adapter. The installer does
not change Ethernet, the hostname or SSH. The initial configuration blocks
client internet access until a proxy is added.

Connect to the new Wi-Fi network and open [the panel](http://10.77.0.1/).
With hostname `geobox`, [geobox.local](http://geobox.local/) is usually also
available. Sign in with the panel password and add a proxy. The panel is also
accessible from the trusted home network; do not forward port 80 to the internet.

Installation records are stored in `/var/lib/geobox-installer/release-*`.
On failure, the new access point is stopped before installer-owned files and
network changes are rolled back. An independent timer starts recovery after
five minutes if the installer has not recorded successful completion. OS
packages remain installed. Files modified by another process are not overwritten.

## Optional iPhone module

Basic proxy routing works without this module. For location simulation, create
a dedicated environment on the Pi; do not overwrite an existing environment
that contains a different version:

```sh
sudo install -d -m 755 /opt/geobox-ios
sudo python3 -m venv /opt/geobox-ios/venv
sudo /opt/geobox-ios/venv/bin/python -m pip install 'pymobiledevice3==11.49.0'
sudo install -d -m 700 /var/lib/geobox/ios
sudo systemctl restart geobox-panel
```

This downloads [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)
and its dependencies. The main package version is pinned, but a complete
dependency lock is not yet available, so the entire Python environment is
not yet reproducible.

Open **Mimic → Подключить iPhone** (“Connect iPhone”) and follow the instructions.
The initial pairing path verified on iOS 27 is **Settings → Privacy & Security
→ Developer Mode → the pairing section**. It is not the empty list under the
separate **Developer → Paired Computers** menu. The PIN appears only in the
panel session that started pairing. The pairing window lasts five minutes
and can be cancelled.

Keep the phone unlocked and connected to GeoBox Wi-Fi. The first location
command may require downloading a developer image and contacting Apple
services. Automatic synchronization is off by default. “Command accepted”
means that the phone acknowledged the request; check the actual result
separately in Maps or [BrowserLeaks Geolocation](https://browserleaks.com/geo).
Native applications may detect software-simulated locations.

The current panel labels are in Russian. Common controls:

| Panel label | Meaning |
| --- | --- |
| Обзор | Overview |
| Прокси | Proxies |
| Устройства | Devices |
| Настройки | Settings |
| Проверить | Check |
| Применить | Apply |
| Подключить iPhone | Connect iPhone |
| Отменить сопряжение | Cancel pairing |

## Update and roll back

For installations created with this installer, extract a new release into a
separate directory and run:

```sh
sudo python3 install.py --check
sudo python3 install.py --update
```

The application code and local release manifest are updated. `/etc/geobox`,
proxy assignments, the panel password, statistics, the Wi-Fi profile and
`/var/lib/geobox/ios` are preserved. Only the panel restarts. An active pairing
or location operation prevents an update. Locally edited code is not overwritten.

Network scripts, firewall rules and systemd template changes require a
dedicated reviewed migration; ordinary `--update` refuses them. Legacy
installations made with `step*.sh` have no release receipt and also require a
migration. They can run `--check`, but passing preflight does not mean that
`--update` is supported.

The update prints the backup directory. Use that exact path to roll back code:

```sh
sudo python3 install.py --rollback /var/lib/geobox-installer/release-BACKUP_NAME_FROM_OUTPUT
```

This is not an uninstall command: a completed initial installation cannot be
removed this way. Keep a separate backup of your settings. Private directories
and pairing records must not be added to a public repository.

## Known limitations

This repository contains the application, installer, build tool and guides.
Private research, deployment history and local test fixtures are excluded.
The installer validates the configuration using `sing-box check` and checks
nftables syntax without applying rules.

Not yet confirmed through full end-to-end testing: installation and reboot on
a clean SD card; updating and rolling back that installation; pairing a new
iPhone entirely through the panel; long-term location persistence. A complete
dependency lock and a project license are also still pending.
