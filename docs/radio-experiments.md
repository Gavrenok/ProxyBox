# Wi-Fi adapters and experimental location beacons

Proxy routing, Wi-Fi reception, and a change in the client's system location are
three separate results. This feature does **not** turn a proxy IP into GPS.

## Select the internet access-point adapter

Open **Wi-Fi → Wi-Fi adapters**. The table shows the interface, driver, USB/built-in
connection and current role. Choose an AP-capable adapter and supported band.
Keep Ethernet upstream connected. The SSID and password are preserved.

After **Try adapter**, reconnect to that SSID, open `http://10.77.0.1/?tab=wifi`
from a device on it, refresh the page and press **Keep adapter** within 120 seconds.
Without confirmation the previous profile is restored. **Stop and restore** also
rolls an unconfirmed change back. A committed choice persists across boots.

The switch updates the firewall, IPv4/IPv6 policy routes, DHCP, RA, client
statistics and diagnostics together. Forwarding remains restricted to the proxy
tunnel. It runs in a separate systemd service; panel restarts do not cancel its
rollback. A journal restores an unfinished change at the next boot before
NetworkManager starts. Do not unplug the selected AP dongle while using it.

A USB connector or an antenna does not guarantee better throughput or range.
Compare actual client throughput at the same distance; advertised PHY rates are
not internet speeds. On the development Pi, the built-in radio and Archer T2U Nano
support 5 GHz; the tested Hoco/RTL8710BU dongle exposes only 2.4 GHz. Chip revisions,
drivers, power and local radio regulations matter. This is not an automatic
"fastest adapter" selector.

On the development Pi 5, switching to the Archer T2U Nano at 5 GHz was tested
with a Windows client obtaining DHCP and opening the panel. The router policy
audit passed, and omitting confirmation restored the built-in AP automatically.
That verifies an AP connection and rollback, not a speed/range improvement. The
new interface-selection path has not undergone a power-loss/reboot hardware test.

## Bounded beacon experiment

This is an opt-in research feature, off by default, with no autostart. It needs a
**separate idle USB radio** with monitor support and working frame injection.
Driver-advertised monitor support alone does not establish injection support.
The internet AP and transmitter cannot share one physical radio. A dongle used
for the AP is therefore unavailable as the beacon transmitter.

In **Wi-Fi → Experimental Wi-Fi beacons**, select the transmitter, a locally
permitted channel (1–11), a duration (10–300 seconds), and your own JSON dataset:

```json
[
  {"bssid": "02:00:00:00:00:01", "ssid": "PB-Test-01"},
  {"bssid": "02:00:00:00:00:02", "ssid": "PB-Test-02"}
]
```

These synthetic addresses are for checking visibility only; they have no
documented location association. The release includes no harvested BSSID lists,
location database credentials, or personal test data. At most 40 distinct unicast
addresses are accepted. All beacons use the selected channel. No deauthentication,
authentication handling, association service, power increase, or automatic AP
BSSID change is performed.

The status **transmitting_unverified** and `submitted` counter mean only that
the driver accepted writes. Confirm reception with a separate receiver. Stop
manually or let the deadline expire; the worker restores the USB radio to its
previous idle managed state. A systemd timeout and independent `ExecStopPost`
cleanup also apply if the worker dies. Cleanup errors remain visible and prevent
another operation until resolved. Reboot returns the radio to its normal driver
configuration; beacons do not restart.

The release implementation was checked with synthetic BSSIDs: a separate USB
receiver saw the beacon, expiry restored managed mode, and killing the transmitter
process with SIGKILL also triggered cleanup. These are radio/lifecycle checks,
not a new successful geolocation test.

## Evidence and limits, 18 November 2026

| Client | Observed result | What is not established |
| --- | --- | --- |
| Unpaired iPhone, tested OS build 24B156 | AirPort saw all 40 test BSSIDs. Location logs contained target-city Wi-Fi fixes and explicit fusion rejection. Maps remained in the original city. | Successful system location change; behavior in an RF shield; other iPhones/builds |
| Paired iPhone | Separate developer-service location simulation had previously changed its location. | This is not evidence for radio spoofing; pairing is a different feature. |
| Android | No controlled client test | Beacon visibility and system location outcome |
| Windows | Browser location was checked after the transmitter stopped | Outcome during a synchronized RF trial |
| macOS | No controlled client test | Beacon visibility and system location outcome |

In the reviewed iPhone logging window, the Wi-Fi provider calculated target fixes
with roughly 21–24 m reported uncertainty. The logs included
`location rejected by LCFusion`, gross-outlier rejection, and filtering of 34 of
40 AP centroids by moving-AP detection in one calculation. The 65 examined fused
outputs stayed in the original city. All 49 found GNSS `validFix` entries in that
window were zero. These records do **not** prove that live GPS was overriding
the beacons. Parsing reported missing oversize records, so the review is not an
exhaustive account of every internal event.

Booting with the test environment already active, including a second set of
addresses not seen in the reviewed earlier captures, also produced no reported
system location change. We do not have a second device log establishing why the
new-address trial failed.

Nearby Wi-Fi, stored history and location-fusion decisions are possible factors;
none was isolated sufficiently to identify a single cause. **Removing nearby
Wi-Fi is not a proven remedy.** An RF-shielded control would test a hypothesis,
not validate a promise of success. Airplane mode is not a measurement of GNSS
reception. Apple describes Location Services as combining multiple sources:
[Location Services and privacy](https://www.apple.com/legal/privacy/data/en/location-services/).

## Testing Android or a computer

Use the same distinction between reception and the final location result on
every platform. Record client model, OS/browser version, test start/end, dataset
revision, scanned BSSIDs/RSSI, network connectivity, and the timestamp/accuracy
of each location result. Keep software location simulators disabled. Compare a
baseline with a timed transmission; do not count a stale map point or IP-country
lookup as a new system location fix.

Use the OS's location API/native map and, separately, the panel's **Mimic** browser
diagnostics or an HTTPS Geolocation API test. Browser permission, Windows/macOS
location settings and application permission must allow that request. A missing
permission or network error is inconclusive. A successful scan is not a successful
location change. Publish platform-specific outcomes, not blanket compatibility.

The implementation uses the public NetworkManager interface:
[nmcli reference](https://networkmanager.dev/docs/api/latest/nmcli.html).
Only the user's own chosen datasets are stored locally, in root-only runtime files.

## Existing installations

This version changes the LAN binding and DHCP configuration. For installations
with an installer receipt, build/extract a new release as described in the README,
then use `sudo python3 install.py --update-network` instead of `--update`.
It backs up code, configuration and receipt and restores them on failed checks.
Unknown local edits or unrelated service changes are still refused. Stop any
adapter/beacon operation first. Legacy installations without a receipt need a
reviewed migration; do not force a clean installation over them.

An old pre-adapter release must only be restored after selecting the built-in
`wlan0` AP again. Otherwise its fixed-interface policy cannot serve a USB AP.
