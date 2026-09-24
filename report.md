# static analysis report

analyzed 2026-09-23 CDT.

this is a static analysis of the supplied `0t46hk.7z`. I did not execute the APK or let any of the recovered code contact the network.

## conclusion

this sample is malicious.

it is a multistage Android RAT/dropper chain. the outer APK is intentionally hostile to normal archive tooling, embeds a second APK, and that second APK contains an encrypted `HSb.jar` stage. decrypting that stage exposes the final RAT payload.

the final payload contains credential overlay support, keylogging, SMS collection, screen control, camera control, SOCKS5 proxying, uninstall protection, and wireless ADB shell functionality.

family attribution is high confidence Mirax/Cifrat lineage based on the architecture and exact C2 command vocabulary. I did not find the exact outer APK hash in the public reports I checked.

## hashes

### original archive

```text
filename: 0t46hk.7z
sha256: 1134f114ad3c9c263ca647b6e832afc8c0a6d7d8c132fb928cbfde44062e045d
```

### outer APK

```text
sha256: a80ab2d066ab34dadeccce369b4ad9e32df5c14dbfbdd9a96acede961d93562f
sha1:   6c0338be737e712c32e2d27c34097fe9574afed2
md5:    b44b372f88d18666eb2199136a436267
package: com.harvdouh.clienttdkar
version: 5.2.6
```

### embedded APK

```text
path inside outer APK: uknown/flykdzt9azm=.apk
sha256: 359e778809e20ddea85f4886fc7f62c3ad921a52f75d4bd2a449f12773857b6e
package: io.xbslmmmp.clientf92mf
version: 1.7.19
```

### hidden payload

```text
HSb.jar encrypted sha256:
e1780c52774f4f7c3676e9352b373b08f9ea4b01875063d7089f28f81c0a2c22

RC4 key:
IdCB

HSb.jar decrypted sha256:
c37125e7933e78fb7b2bb3220e34088c8f194e82e6fe60b37c144fc918a1ed26
```

recovered final DEX files:

```text
classes.dex
5300c169ca091f6b02910463e7b74fcf4c6d0a6a3aca565d74f6110d5761feed

classes2.dex
5037a2819b5e676372809a70b7227bf9bc8f0b0d9a6b5f0a7109939dd0749888

classes3.dex
f461761189474e939fee59c1a719bc9cb0b7daed943b26d5b7a35b6a3c942355
```

## signing certificate

both the outer APK and embedded APK use the same certificate.

```text
subject: C=中国, ST=江苏, L=南京, O=np, OU=np, CN=np
issuer:  C=中国, ST=江苏, L=南京, O=np, OU=np, CN=np
serial:  045FF9A3
sha256 fingerprint:
49:26:82:F8:77:60:7E:E9:9D:F2:DD:D2:BD:59:53:FD:72:7B:DF:6E:19:D3:97:DE:9D:BB:AF:D5:82:BC:AD:75
not before: 2021-04-25 09:03:56 GMT
not after:  3020-08-26 09:03:56 GMT
```

the ridiculous certificate lifetime is worth noting, but obviously a weird self-signed cert by itself does not prove malware. the behavior does that just fine.

## stage 1: outer APK

package:

`com.harvdouh.clienttdkar`

this stage is heavily padded/booby-trapped for analysis.

### archive abuse / tarpit

I found 434 fake `classes00*.dex` entries in the outer archive. each one is advertised as exactly 1 MiB in the ZIP listing. the normal ZIP parser also rejects malformed central-directory extra fields.

there are only three real outer DEX files that matter:

```text
classes.dex
classes2.dex
classes3.dex
```

there are also large numbers of junk-looking assets and the same general padding scheme continues into the second APK.

this is not subtle. tooling that trusts the central directory or blindly tries to decompile every advertised DEX gets buried in garbage.

### outer manifest capabilities

interesting permissions include:

```text
android.permission.REQUEST_DELETE_PACKAGES
android.permission.RECEIVE_BOOT_COMPLETED
android.permission.REQUEST_INSTALL_PACKAGES
android.permission.QUERY_ALL_PACKAGES
android.permission.MANAGE_EXTERNAL_STORAGE
android.permission.PACKAGE_USAGE_STATS
android.permission.INTERNET
android.permission.WAKE_LOCK
```

interesting components include:

- a disabled activity alias that can register as `android.intent.category.HOME`
- an exported direct-boot-aware receiver for `PACKAGE_ADDED` and `PACKAGE_REPLACED`
- a `VpnService`
- multiple foreground services

its manifest also explicitly queries the package name of the embedded stage:

`io.xbslmmmp.clientf92mf`

## stage 2: embedded APK

package:

`io.xbslmmmp.clientf92mf`

this manifest is enough on its own to make the app extremely bad news.

### permissions

confirmed permissions include:

```text
android.permission.CAMERA
android.permission.READ_PHONE_STATE
android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
android.permission.RECEIVE_BOOT_COMPLETED
android.permission.WRITE_SMS
android.permission.SEND_SMS
android.permission.RECEIVE_SMS
android.permission.RECEIVE_MMS
android.permission.WRITE_CONTACTS
android.permission.CALL_PHONE
android.permission.QUERY_ALL_PACKAGES
android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION
android.permission.FOREGROUND_SERVICE_ACCESSIBILITY
android.permission.FOREGROUND_SERVICE_CAMERA
android.permission.ACCESS_NOTIFICATION_POLICY
android.permission.WAKE_LOCK
```

### components

confirmed manifest components include:

- exported Accessibility Service protected by `BIND_ACCESSIBILITY_SERVICE`
- Device Admin receiver protected by `BIND_DEVICE_ADMIN`
- boot receivers
- exported `SMS_RECEIVED` receiver
- exported `SMS_DELIVER` receiver
- WAP push receiver
- notification listener service protected by `BIND_NOTIFICATION_LISTENER_SERVICE`
- `ScreenCaptureRequestActivity`
- foreground services for camera and media projection
- an activity running in an `:overlay` process with task affinity `app.htmloverlay`
- separate task affinities for pattern, PIN, and password UI

that is a very specific set of capabilities for an app pretending to be something normal.

## stage 3: encrypted HSb.jar

inside the second stage is an encrypted `HSb.jar` payload.

static inspection of the unpacker exposes:

```text
HSb.jar
IdCB
```

its decryption routine is RC4. decrypting the blob with key `IdCB` produces a valid JAR containing three valid DEX files.

this is the point where the actual RAT functionality becomes easy to see without fighting the outer packer.

## final RAT behavior

most of the interesting custom functionality is visible in the recovered final `classes2.dex`.

### C2 protocol

confirmed strings:

```text
AndroidClient-Control/1.0
AndroidClient-Data/1.0
AndroidClient-HttpPoll/1.0
X-Channel-Type
X-Session-ID
/control
/data
:31192/api/device/poll
vbnsajiqlas.com
```

static reconstruction of the config gives:

```text
control WebSocket: wss://vbnsajiqlas.com:27911/control?sessionId=...
data WebSocket:    wss://vbnsajiqlas.com:45598/data?sessionId=...
HTTP polling:      https://vbnsajiqlas.com:31192/api/device/poll
```

so it uses separate control and bulk-data channels, with HTTP polling as a fallback.

### command surface

these command names are present in the recovered payload:

```text
addHtmlInjectionConfig
collectSmsNow
enableUninstallProtection
disableUninstallProtection
startVncScreenSharing
startCamera
startSmsCollection
getKeyguardInfo
socks5_enable
socks5_status_request
```

there are many more, but those are enough to identify what this thing is doing.

### credential theft / HTML injection

there is an explicit HTML overlay system. the stage 2 manifest even dedicates a separate overlay process to it.

commands include `addHtmlInjectionConfig`, and the recovered code contains logic for collecting data submitted through the fake UI. this is credential theft functionality, not just a generic WebView.

### keylogging

recovered strings/classes include:

```text
KeylogBatch
KeylogEntry
Keylogger initialized successfully
```

keylogging is implemented as part of the RAT, not inferred from the accessibility permission alone.

### SMS theft

this is backed up in several places:

- SMS permissions in the manifest
- `SMS_RECEIVED` and `SMS_DELIVER` receivers
- `collectSmsNow`
- `startSmsCollection`

### remote screen control

confirmed command:

`startVncScreenSharing`

plus screen-capture/media-projection components in the installed stage.

### camera

confirmed command:

`startCamera`

plus camera permission and camera foreground-service capability.

### uninstall protection

confirmed commands:

```text
enableUninstallProtection
disableUninstallProtection
```

this lines up with the Device Admin and Accessibility pieces in the manifest.

### SOCKS5 proxy

confirmed commands/classes include:

```text
socks5_enable
socks5_status_request
socks5TunnelManager
```

so an infected phone can be used as a proxy node, which is one of the more distinctive Mirax features.

### wireless ADB / shell

this build also has a substantial wireless ADB implementation.

recovered strings include:

```text
:wireless-adb-identity:v1
ADB shell command cannot be blank
ADB shell command exceeds 500 characters
ADB shell command failed
ADB shell command must be a single line
ADB shell command returned no data
Only adb shell commands are supported
```

classes include a pure Java ADB client, wireless ADB pairing/identity handling, and `runAdbShellCommand` code paths.

that is a real remote shell capability if the malware succeeds in getting the device into the state it expects.

## persistence

this sample has plenty of persistence inside the normal Android userspace install:

- boot receivers
- Accessibility Service
- Device Admin support
- battery-optimization bypass request
- WorkManager/system job components
- uninstall protection logic

I did not find evidence in the recovered sample of boot image, recovery, `/system`, `/vendor`, or firmware modification.

so my current assessment is:

```text
reboot: survives
ordinary user removal: actively resists it
genuine factory reset: should remove it
trusted full firmware reflash: stronger cleanup if system compromise is suspected
```

that last part is an assessment from the code recovered here. it does not prove that some totally separate exploit could never have been used on an infected device.

## family attribution

### Mirax

Cleafy published a Mirax analysis with the same split WebSocket control/data architecture and the same distinctive commands, including:

```text
addHtmlInjectionConfig
collectSmsNow
enableUninstallProtection
disableUninstallProtection
startCamera
startSmsCollection
startVncScreenSharing
socks5_enable
socks5_status_request
```

source:

https://www.cleafy.com/cleafy-labs/mirax-a-new-android-rat-turning-infected-devices-into-potential-residential-proxy-nodes

### Cifrat

CERT Polska published an April 2026 analysis of a sample they called `cifrat`. their sample used different packages, hashes, encryption key, and C2, but the structure is extremely close:

- multistage Android dropper
- embedded second APK
- hidden RC4-like final payload
- Accessibility controlled RAT
- split control/data WebSockets
- HTML injection
- SMS collection
- screen streaming
- camera control
- SOCKS5 tunneling

source:

https://cert.pl/en/posts/2026/04/cifrat-analysis/

CERT's sample used RC4-like key `mLYQ` and C2 `otptrade.world`. this sample uses key `IdCB` and C2 `vbnsajiqlas.com`.

### assessment

high confidence this sample belongs to the same Mirax/Cifrat lineage.

I am not claiming this exact SHA-256 is one of the samples in either writeup. it is not. the package names, C2, and encryption key are rotated here.

## limitations

- static analysis only
- I did not connect to the C2
- I did not execute the app in an emulator or physical device
- the packer intentionally contains malformed/junk archive data, so there may be additional garbage entries I did not bother normalizing once the real stages were recovered
- family attribution is based on recovered architecture, command vocabulary, and implementation overlap, not access to the malware author's source tree
