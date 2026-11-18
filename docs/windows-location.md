# Windows location: local sensor evidence

On 18 November 2026, a bounded test changed the native
`Windows.Devices.Geolocation.Geolocator` output on Windows build **26200.9974**
to the public test coordinates **1.5536, 110.3593 (Kuching)**. This used a local
GPSDirect sensor with a loopback NMEA source. It did not use Wi-Fi beacons,
browser DevTools, an iPhone pairing, or a connection to the Pi.

## Observed result

| Stage | Observation |
| --- | --- |
| Baseline | Fresh non-target location, source `WiFi`, reported accuracy 118 m |
| Driver | Signed GPSDirect v2, driver version 11.0.55.985; Windows device status OK, problem code 0 |
| Input | One TCP connection to `127.0.0.1`; 74 samples containing GPGGA and GPRMC sentences |
| Native API | 14 consecutive fresh target positions after input began; source `Satellite`; reported accuracy 1 m |
| Timing | Target samples dated 09:36:24–09:37:31 UTC; their ages when read were approximately 0.85–1.70 s |
| Cleanup | Test device absent after removal; at 09:38:42 UTC a fresh non-target `WiFi` position returned |

`Satellite` is the source classification returned for the simulated sensor.
There was no reception or transmission of satellite signals. The reported 1 m
accuracy is a simulator/driver claim, not a measurement of physical accuracy.

The measurement kept a `GeoCoordinateWatcher(High)` alive and repeatedly queried
a `Geolocator` with `DesiredAccuracy=High`, zero requested cache age and a bounded
timeout. Microsoft documents requesting
[high accuracy to activate GPS acquisition](https://learn.microsoft.com/en-us/windows/uwp/maps-and-location/guidelines-and-checklist-for-detecting-location).
The first trial used default accuracy and never received a source connection;
that earlier outcome did not establish that Windows rejected simulated input.
The later run changed the request strategy, but did not isolate every variable
well enough to prove a unique cause of the earlier missing connection.

The vendor uninstaller returned `0xC0000005` after removing the device. Device
absence and the subsequent native location result were checked independently.
The signed driver package can remain in DriverStore; this was not a full purge
of every installed file or setting.

## Product boundary

- The result confirms the Windows location API on this machine. Individual
  browsers and applications, their permissions, caches and independent location
  providers still need separate verification. It is not a universal override of
  every application's location logic or its public IP address.
- Automatic synchronization with a ProxyBox proxy is **not implemented** in this
  experiment. The target was a fixed public test location.
- There is no persistent Windows companion in the Pi release. The test removed
  its temporary device; merely joining the Pi's Wi-Fi does not activate it.
- [GPSDirect](https://www.gpssensordrivers.com/) is third-party software with
  evaluation licensing and separate redistribution terms. Its binaries and
  license material are not included in this repository. The test did not disable
  Secure Boot, require test-signing mode, or use a restricted override token.

The separate [Wi-Fi beacon trials](radio-experiments.md) remain negative for the
tested Windows client and unpaired iPhone. This local Windows result does not
change their status.
