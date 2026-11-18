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
| Windows, Wi-Fi beacon trial | During a subsequent live beacon trial, scans matched up to 25/40 test BSSIDs. Native Windows Geolocator returned the original city, source `WiFi`, reported accuracy 137–158 m. | Successful radio-based system location change; reason for rejecting or not using the target environment |
| macOS | No controlled client test | Beacon visibility and system location outcome |

The Windows result uses the native `Windows.Devices.Geolocation.Geolocator`
API, separately from BrowserLeaks. Both calls requested zero maximum cache age
and a 20-second timeout. Result timestamps were close to the request times;
one preceded its request by about 0.8 seconds. Scans are snapshots and did not
show all 40 addresses at once. This is a negative result under the tested
conditions, not proof of incompatibility with every Windows device.

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

## Existing approaches reviewed

- [SkyLift](https://github.com/adamhrv/skylift) is a public beacon-spoofing
  implementation with historical phone demonstrations. Its
  [January 2025 discussion](https://github.com/adamhrv/skylift/issues/20) includes
  the author's request for current success reports. Neither establishes success
  on our current Windows/iPhone setup. A forum claim about closed firmware is
  not a reproducible implementation or a reason to mark this feature supported.
- [Windows GeolocationProvider](https://learn.microsoft.com/en-us/uwp/api/windows.devices.geolocation.provider.geolocationprovider)
  supports an override for consumers of Windows location services. Microsoft
  documents a `runFullTrust` capability and a Limited Access Feature token.
  A direct call on our Windows build 26200.9974 returned `AccessDenied`; it did
  not change the location. This is a local software mechanism, not a router setting.
- [FakeGPS](https://github.com/juliankay/FakeGPS) is an older virtual Windows GPS
  driver. Its author marks it unmaintained and requires test-signing mode.
  It has not been installed or validated on our machine.
- [GPSDirect](https://www.gpssensordrivers.com/) is a separate vendor's Windows
  sensor driver, documenting simulated/fixed positions and a TCP NMEA source.
  It is a candidate for a local Windows companion, not a feature shipped here.
  In an initial local trial on Windows build 26200.9974, the signed v2 driver
  installed and the test device was removed afterwards. However, it never
  connected to the loopback NMEA source (zero connections/frames sent), while
  Windows continued returning a Wi-Fi location. That run is inconclusive about
  accepting a simulated GPS fix: no input reached the driver. The first probe
  also used default accuracy instead of an explicit high-accuracy consumer.
  A later trial held a high-accuracy consumer open: the source sent 74 NMEA
  samples, and Windows returned 14 consecutive fresh target-city positions with
  source `Satellite`. After removal, a fresh `WiFi` position returned. This is a
  successful local sensor test, not a radio result or a guarantee for every app.
  A later run resolved the current proxy's coordinates at startup; Windows and
  the tested browser returned those coordinates with fresh timestamps. Continuous
  synchronization after proxy changes remains unimplemented. The vendor uninstaller returned
  an error after device removal; removal was checked separately, and the driver
  package can remain in DriverStore. See [Windows evidence](windows-location.md).
  The vendor offers evaluation licensing; redistribution has separate terms.
- [Chrome DevTools Sensors](https://developer.chrome.com/docs/devtools/sensors)
  provides a browser testing override. This does not fulfill a requirement for
  Windows system location and is not counted as radio success.

The local Windows sensor trial establishes a separate working path on the tested
machine. It does not resolve the negative Wi-Fi beacon result. A Windows companion
would require local installation and its own explicit controls; joining the Pi's
Wi-Fi would not itself install or enable it.

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
