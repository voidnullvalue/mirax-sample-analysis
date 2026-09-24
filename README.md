# mirax sample analysis

short version: this APK is malware. not "probably malware". the final payload is an Android RAT with credential overlays, keylogging, SMS collection, screen control, camera access, SOCKS5 proxying, uninstall protection, and ADB shell support.

I only did static analysis. I did not install or execute the sample.

## sample

original upload:

`0t46hk.7z`

SHA-256:

`1134f114ad3c9c263ca647b6e832afc8c0a6d7d8c132fb928cbfde44062e045d`

outer APK SHA-256:

`a80ab2d066ab34dadeccce369b4ad9e32df5c14dbfbdd9a96acede961d93562f`

outer package:

`com.harvdouh.clienttdkar`

embedded APK package:

`io.xbslmmmp.clientf92mf`

current C2 found in the final payload:

`vbnsajiqlas.com`

## infection chain

```text
0t46hk.7z
  -> app.apk
     -> malformed/padded APK with hundreds of fake DEX entries
     -> embedded APK: uknown/flykdzt9azm=.apk
        -> io.xbslmmmp.clientf92mf
        -> encrypted HSb.jar
           -> RC4 key: IdCB
           -> decrypted HSb.jar
              -> classes.dex
              -> classes2.dex
              -> classes3.dex
                 -> final RAT
```

434 fake `classes00*.dex` entries in the outer APK claim to be 1 MiB each. normal ZIP parsing also chokes on malformed central-directory metadata. this looks intentional and is a pretty effective analysis tarpit if tooling blindly trusts the archive metadata.

## what it can do

confirmed from the manifests and recovered final DEX code/strings:

- accessibility service abuse
- device admin support
- boot persistence
- SMS receive/deliver/send/write
- notification listener
- screen capture and VNC-style screen control
- HTML injection / credential overlays
- keylogging
- camera access
- app/package enumeration
- uninstall protection
- SOCKS5 tunneling
- wireless ADB pairing and ADB shell commands
- split WebSocket control/data C2
- HTTP polling fallback

see [report.md](report.md) for the full breakdown.

IOCs are under [iocs/](iocs/).

## family

high confidence this is in the Mirax/Cifrat lineage.

Cleafy's Mirax writeup documents the same command vocabulary and the same control/data WebSocket design:

https://www.cleafy.com/cleafy-labs/mirax-a-new-android-rat-turning-infected-devices-into-potential-residential-proxy-nodes

CERT Polska's April 2026 `cifrat` analysis describes an extremely similar chain: multistage Android dropper, second APK, RC4-like hidden payload, accessibility RAT, HTML injection, SMS theft, camera, screen streaming, SOCKS5, and dual WebSocket C2:

https://cert.pl/en/posts/2026/04/cifrat-analysis/

I did not find this exact outer APK SHA-256 in the public reports I checked. so this looks like another build/repack/campaign instance, not one of the exact published samples.

## important

I am not putting the live malware sample in this repo. hashes and analysis only.
