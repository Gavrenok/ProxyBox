# ProxyBox

**English** | [Русский — пошаговая установка](README.ru.md)

Connect your phone or Mac to a Raspberry Pi Wi-Fi hotspot and route its internet
traffic through your chosen proxy. Manage it from a local web page.
The panel currently says **GeoBox**; this is normal. This independent project
does not distribute the commercial GeoBox firmware.

> **Preview, not a verified one-click appliance.** The app works on our Pi 5,
> but the new installer has not passed a complete clean-card installation and
> reboot test. Start with a spare SD card. Existing users: use the update section,
> not the fresh-install commands below.

**Start here:** [Equipment](#before-you-start) · [Installation](#1-write-the-sd-card)
· [iPhone location](#optional-iphone-location) · [Troubleshooting](#if-something-goes-wrong)
· [Updates](#update-and-roll-back)

![Connection diagram: home router by Ethernet to Pi, phone or Mac by Wi-Fi to Pi; panel at 10.77.0.1](docs/images/setup-en.png)

## Before you start

| You need | What it is for |
| --- | --- |
| Raspberry Pi 5 and a suitable power supply | Runs the gateway |
| Spare microSD card and card reader | A clean 64-bit Raspberry Pi OS based on Debian 13 |
| Ethernet cable and home router with internet | Router LAN port → Pi Ethernet port; keep it connected |
| Windows PC or Mac on the same home network | Writes the card and opens an SSH terminal |
| A working proxy from your provider | The project does not supply proxies |
| Phone or Mac | Connects to the new hotspot after installation |

**Three passwords:** the Pi login password is for SSH/`sudo`; later you create a
Wi-Fi password and a separate panel password. Keep all three. Typing an SSH or
`sudo` password shows no characters, not even dots — type it and press Enter.

The Pi receives internet by **Ethernet**, not its built-in Wi-Fi. Its Wi-Fi is
reserved for your devices. A display and keyboard attached to the Pi are not required.

## 1. Write the SD card

**On your Windows PC or Mac:** open [Raspberry Pi Imager](https://www.raspberrypi.com/software/).

1. Select **Raspberry Pi 5**.
2. Choose **Raspberry Pi OS Lite (64-bit)** based on **Debian 13 / Trixie**.
3. Select your **spare SD card**. Writing the image erases that card.
4. In customization, set hostname **`geobox`**, username **`pi`**, and your own strong password.
5. Enable **SSH** with password authentication, or use your existing SSH key.
6. Write the card, eject it, and insert it into the Pi.
7. Connect the Pi to a **LAN port** on your router using Ethernet, then connect power.

Allow the first boot to finish. These are example names for following this guide;
if you choose another username or hostname, replace them in the SSH command.
[Official Imager setup instructions](https://www.raspberrypi.com/documentation/computers/getting-started.html).

## 2. Connect to the Pi

**On Windows:** open PowerShell. **On Mac:** open Terminal. Run:

```sh
ssh pi@geobox.local
```

For the first connection, confirm the host fingerprint belongs to your Pi before
accepting it. Enter the Pi login password if prompted.

**Checkpoint:** the prompt now looks like `pi@geobox:~ $`.
**All command blocks below run in this SSH window, on the Pi.** Do not paste them
into a fresh Windows PowerShell window. Run each block in order; if a command
fails, stop and check the troubleshooting table before continuing.

## 3. Prepare the Pi

```sh
sudo apt-get update
sudo apt-get install -y git python3 python3-venv network-manager dnsmasq nftables iproute2 iw curl ca-certificates avahi-daemon avahi-utils rfkill
sudo systemctl stop dnsmasq
sudo systemctl enable --now NetworkManager avahi-daemon
sudo nmcli radio wifi on
sudo raspi-config
```

In `raspi-config`, set **WLAN Country** to the country where the hardware is
physically located, then Finish. If it reboots, reconnect using step 2.
This sets radio regulations, not your proxy's country.

Add the [official sing-box package repository](https://sing-box.sagernet.org/installation/package-manager/)
and install the version this project checks:

```sh
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
sudo chmod a+r /etc/apt/keyrings/sagernet.asc
sudo tee /etc/apt/sources.list.d/sagernet.sources > /dev/null <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
sudo apt-get update
sudo apt-get install sing-box=1.14.4
sudo apt-mark hold sing-box
sudo systemctl disable --now sing-box.service
sing-box version
```

**Checkpoint:** the first version line must be `sing-box version 1.14.4`.
If APT says this version is unavailable, stop rather than installing an untested
version. OS package changes are outside the ProxyBox installer's rollback.

## 4. Download and check ProxyBox

**Still on the Pi:** this downloads the source and builds the installation
archive locally. No Git or Python installation on your Windows PC/Mac is needed.

```sh
cd ~
git clone https://github.com/Gavrenok/ProxyBox.git
cd ProxyBox
python3 pi/build_release.py --output dist/geobox-preview.tar.gz
mkdir ~/proxybox-install
tar -xzf dist/geobox-preview.tar.gz -C ~/proxybox-install
cd ~/proxybox-install
sudo python3 install.py --check
```

**Checkpoint:** the last line includes `"preflight": "passed"` and `"changes": false`.
This checks prerequisites; it has not installed ProxyBox yet. `STOP:` means you
must fix the reported problem first. If `existing_installation` is `true`, use
the update instructions instead. Do not reuse a nonempty extraction directory.

## 5. Install and choose passwords

**In the same SSH window**, run:

```sh
sudo python3 install.py --install --ssid 'My ProxyBox'
```

The installer asks for the new Wi-Fi password and panel password with hidden input.
Use 8–63 printable ASCII characters for Wi-Fi (Latin letters, digits and symbols)
and at least 12 characters for the panel. Each password is entered twice.
`My ProxyBox` is the Wi-Fi name you will select on the phone. You can change the
name in this command. The default is 2.4 GHz; experienced users can add `--band a`
for 5 GHz if their country's channels support it.

**Checkpoint:** the final JSON includes `"installed": true` and a backup path.
Keep that path. Keep Ethernet connected. Internet on the new Wi-Fi is deliberately
blocked until you add a working proxy in the next step.

## 6. Open the panel and add your proxy

**On your phone or Mac:**

1. Join **My ProxyBox** using the Wi-Fi password you just created. Stay connected
   if the device warns that the network has no internet yet.
2. Open **[http://10.77.0.1/](http://10.77.0.1/)** in Safari or another browser.
   Type it into the address bar, not a search box. It uses **http**, not https.
3. Sign in with the **panel password** from step 5.
4. Open **Прокси** (Proxies), paste your provider's proxy, and press **Проверить** (Check).
5. If the check succeeds, press **Применить** (Apply), then wait for the result.
6. Open **Обзор → Проверить выход** (Overview → Check exit).

Example input format — **not a working proxy**:

```text
socks5://YOUR_LOGIN:YOUR_PASSWORD@proxy.example:1080
```

Paste the real string supplied by your provider. Never post it in a GitHub issue
or screenshot. [http://geobox.local/](http://geobox.local/) is an alternative address
when local hostname resolution works.

**Checkpoint:** an external page opens on the client, and the exit check shows
your proxy's address. For a client-side comparison, open [BrowserLeaks IP](https://browserleaks.com/ip).
Test on the device connected to **My ProxyBox**, not your PC on the home Wi-Fi.
The panel is also available on your trusted home LAN; do not forward its port 80
from your router to the internet.

## Optional: iPhone location

**Skip this entire section if you only need internet through a proxy.** Developer
Mode and pairing are required for our iPhone location feature, not basic routing.
Mac system-location simulation is not implemented.

![iPhone setup sequence: enable Developer Mode, pair using the panel PIN, apply coordinates, explicitly enable automatic updates](docs/images/iphone-en.png)

### A. Install the optional component

**On the Pi, in SSH**, run this once on a new installation. Do not overwrite an
existing Python environment with a different version:

```sh
sudo install -d -m 755 /opt/geobox-ios
sudo python3 -m venv /opt/geobox-ios/venv
sudo /opt/geobox-ios/venv/bin/python -m pip install 'pymobiledevice3==11.49.0'
sudo install -d -m 700 /var/lib/geobox/ios
sudo systemctl restart geobox-panel
```

This downloads [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) and
dependencies. The main version is pinned; a complete dependency lock is still pending.

### B. Pair the phone once

1. On iPhone, enable **Settings → Privacy & Security → Developer Mode**.
   Confirm it after a restart if requested. If that option is missing, stop here;
   this guide does not establish a way to enable it on every unprepared phone.
2. Join **My ProxyBox** and leave the phone unlocked.
3. In the panel, open **Mimic → Подключить iPhone** (Connect iPhone).
4. On the tested iOS 27 setup, pairing was under **Privacy & Security → Developer
   Mode → the pairing section**. The separate **Developer → Paired Computers**
   screen stayed empty. Menu names may differ on other versions.
5. Select GeoBox and enter the six-digit PIN displayed in the panel. The pairing
   window lasts five minutes; the PIN is only shown to the session that started it.

### C. Apply coordinates — and turn on automatic updates if wanted

1. Under the paired phone, press **По текущему прокси** (Use current proxy).
2. Wait for the result. The first command may download a developer image and
   contact Apple; keep the phone unlocked and on the hotspot.
3. Open [BrowserLeaks Geolocation](https://browserleaks.com/geo) on that phone,
   allow location access and check the new coordinates.
4. **Want coordinates to follow proxy changes? Press Включить автообновление
   (Enable automatic updates). Verify the line says включено (enabled).**

**A one-time “Use current proxy” command does not enable automatic updates.**
Without auto-update, the previous coordinates can remain after changing proxies.
When the phone is unavailable, a new location may not be delivered immediately.
An unknown command outcome stops automatic retries; inspect the phone and panel status.
Auto-update follows proxy-profile changes, not every invisible IP rotation within
the same provider configuration.

**Вернуть реальную** (Restore real location) queues a reset and disables auto-update.
Simply disabling auto-update does not clear the last simulated coordinates.
“Command accepted” is an acknowledgement, not a readback of the phone's location.
Native apps may detect software simulation. Long sleep/reboot behavior is not fully tested.

## If something goes wrong

| What you see | What to do next |
| --- | --- |
| `geobox.local` cannot be found over SSH | Find the Pi's Ethernet address in your router's client list; use `ssh pi@ADDRESS` with that actual address. |
| Password typing appears blank | Normal for SSH and sudo. Type the password and press Enter. |
| `mkdir` says the folder already exists | Stop. Use a new empty folder and adjust later paths; do not unpack over old files. |
| `STOP:` or a failed package command | Keep the exact error; do not continue or substitute dependency versions at random. |
| New Wi-Fi has no internet | Add/apply a working proxy first. If already configured, use **Обзор → Почему нет интернета?**. |
| Panel does not open | Join **My ProxyBox** and try **http://10.77.0.1/**; leave Ethernet connected. |
| Proxy changed but iPhone's map did not | Check **Mimic → Включить автообновление**, phone connectivity and the last command status. |
| A Google button shows an unexpected language | Language is not a location test. Compare IP and browser language in ordinary/private tabs; don't infer a leak from the button alone. |
| IP country changed but GPS/time zone/language did not | These are separate settings. Basic proxy routing only changes the network route. |

When asking for help, share the failed step and error text. Hide proxy passwords,
Telegram tokens/chat IDs, pairing PINs and device identifiers. Do not upload `/etc/geobox`
or `/var/lib/geobox/ios`. Experimental radio/firmware tools are not part of this release.

## Update and roll back

Only for installations originally created by this installer. In SSH on the Pi,
download the latest sources and extract a new archive into a new directory:

```sh
cd ~/ProxyBox
git pull --ff-only
python3 pi/build_release.py --output dist/geobox-preview.tar.gz
proxybox_stage=$(mktemp -d "$HOME/proxybox-update.XXXXXX")
tar -xzf dist/geobox-preview.tar.gz -C "$proxybox_stage"
cd "$proxybox_stage"
```

Then check and update. Stop if the check fails:

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

The archive includes both guides and their images for offline viewing. Only
explicitly listed source files and diagrams are packaged; runtime secrets and
firmware are excluded. Its SHA256 manifest detects corruption, not publisher identity.

For contributors, the packaging and installer tests use temporary files and mock
network/service commands; they do not install anything on the host:

```sh
python3 -m unittest discover -s pi/tests -p 'test_release_*.py'
```

## Known limitations

This repository contains the application, installer, build tool and guides.
Private research, deployment history and local test fixtures are excluded.
The installer validates the configuration using `sing-box check` and checks
nftables syntax without applying rules.

Not yet confirmed through full end-to-end testing: installation and reboot on
a clean SD card; updating and rolling back that installation; pairing a new
iPhone entirely through the panel; long-term location persistence. A complete
dependency lock and a project license are also still pending.

<details>
<summary>Features and technical requirements</summary>

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


</details>
