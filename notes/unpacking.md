# unpacking notes

this is the part that wasted time.

## outer container

input was a 7z archive:

`0t46hk.7z`

it contains `app.apk`.

## app.apk is intentionally annoying

normal ZIP parsing fails on malformed central-directory extra fields.

the ZIP listing advertises 434 fake `classes00*.dex` entries. each one claims to be 1,048,576 bytes. there are also piles of junk-looking asset entries.

blindly feeding the whole thing to normal APK tooling is a trap. parse local file headers, identify real DEX magic, and ignore the advertised fake DEX set.

real outer DEX files recovered:

```text
classes.dex
classes2.dex
classes3.dex
```

## embedded APK

real outer code/resources lead to:

`uknown/flykdzt9azm=.apk`

SHA-256:

`359e778809e20ddea85f4886fc7f62c3ad921a52f75d4bd2a449f12773857b6e`

package:

`io.xbslmmmp.clientf92mf`

this second APK is signed with the same cert as the outer APK.

## encrypted final stage

inside the second stage is `HSb.jar`.

hardcoded values recovered from the unpacker:

```text
payload: HSb.jar
key: IdCB
```

the routine is RC4. standard 256-byte S-box initialization, key scheduling, then PRGA XOR over the payload.

encrypted SHA-256:

`e1780c52774f4f7c3676e9352b373b08f9ea4b01875063d7089f28f81c0a2c22`

decrypted SHA-256:

`c37125e7933e78fb7b2bb3220e34088c8f194e82e6fe60b37c144fc918a1ed26`

once decrypted, it is a valid ZIP/JAR and contains three valid Dalvik DEX files.

```text
classes.dex
classes2.dex
classes3.dex
```

`classes2.dex` contains most of the custom RAT code and the useful C2/command strings.

## quick strings worth checking

```text
vbnsajiqlas.com
AndroidClient-Control/1.0
AndroidClient-Data/1.0
AndroidClient-HttpPoll/1.0
X-Channel-Type
X-Session-ID
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
KeylogBatch
KeylogEntry
Only adb shell commands are supported
```

once those show up in the decrypted DEX there is not much ambiguity left about what the payload is.
