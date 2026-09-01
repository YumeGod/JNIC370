# JNIC 3.7.0 License Analysis

This repository documents a Windows x64 reverse-engineering analysis of `jnic-3.7.0.jar` and includes a self-contained modified build, `jnic-3.7.0-YumeCloud.jar`.

The analysis focused on JNIC's native implementation and license system: how the embedded native libraries are stored and loaded, where license validation occurs, how `jnic.licence` is processed, how activation and HWID generation work, and how the engine behaves when its native code is modified during startup.

The investigation ultimately identified the native license factory and demonstrated that it can be replaced after JNIC completes its integrity-sensitive initialization while allowing the remainder of the application to execute normally.

## Target

| Property            | Value                                                              |
| ------------------- | ------------------------------------------------------------------ |
| Original JAR        | `jnic-3.7.0.jar`                                                   |
| SHA-256             | `7D8141A0FF1A78FAF12DAFEE9C53682FF608B1E91D0C8A47CFBCC0B88614F3A1` |
| Size                | 6,872,306 bytes                                                    |
| Original main class | `dev.jnic.be`                                                      |
| Modified JAR        | `jnic-3.7.0-YumeCloud.jar`                                         |
| SHA-256             | `3746E7C43601A0F57E6DE36EDA61E601E59753F33A7A8028D47FFEB3EEDD770D` |
| Target platform     | Windows x64                                                        |
| Java version used   | JDK 17.0.10                                                        |

The modified package is specific to the analyzed JNIC 3.7.0 Windows x64 engine. Native addresses and implementation details documented below should not be assumed to apply to other JNIC releases.

## Quick Start

Requirements:

* Windows x64
* Java 17

Run the modified package:

```powershell
java -jar .\jnic-3.7.0-YumeCloud.jar
```

Expected license-stage output:

```text
INFO: Licence: YumeCloud (standard)
INFO: Expires: 8888-88-88
```

The package does not require an external Frida session, Python, or a `jnic.licence` file.

If execution continues to compiler discovery and reports `No usable compiler found`, that is a separate JNIC compiler dependency rather than a license failure.

---

## Embedded Native Libraries

Although JNIC is distributed as a Java JAR, most of its important implementation is not ordinary Java bytecode.

The visible classes contain heavily obfuscated names and many important methods are declared `native`. Their implementations are stored in a compressed multi-platform native payload embedded inside the JAR.

The relevant resource is:

```text
dev/jnic/lib/3273ada3-3474-4e4e-9623-319038d7e4bb.dat
```

### Extracting the Native Payload

Inspection of `dev.jnic.dHQvOm.JNICLoader` showed that the resource is decompressed as a raw LZMA2 stream.

Decompression produces:

```text
32,608,048 bytes
```

containing native images for multiple supported platforms.

`JNICLoader` determines the current operating system and architecture, selects an offset and length inside this decompressed payload, writes that range to a temporary file, and loads it through:

```java
System.load(...)
```

For Windows x64, the selected range is:

```text
offset = 0
length = 7,558,656 bytes
range  = [0, 7,558,656)
```

The first bytes of the decompressed payload are:

```text
4D 5A
MZ
```

confirming that the Windows PE begins directly at offset `0`.

The Windows x64 engine can therefore be recovered independently of the JAR by carving the first `7,558,656` bytes:

```text
jnic-3.7.0.jar
        ↓
embedded .dat resource
        ↓
raw LZMA2 decompression
        ↓
32,608,048-byte multi-platform payload
        ↓
bytes [0, 7,558,656)
        ↓
Windows x64 PE32+ engine
```

### Windows Engine

The extracted image uses:

```text
Image base: 0x180000000
```

and contains JNIC's native implementation, including:

* `JNI_OnLoad`
* per-class `$jnicLoader` entry points
* native methods registered through JNI
* initialization code
* license handling
* the remainder of JNIC's native implementation

An initial IDA survey identified approximately:

```text
6,577 functions
1,729 strings
95 $jnicLoader entry points

JNI_OnLoad = 0x18056e85c
```

Some functions are extremely large; `JNI_OnLoad` alone is approximately 553 KB. This, combined with control-flow flattening and generated native code, makes whole-function decompilation impractical as the only analysis technique.

The engine also performs much of its networking, cryptography, and file handling by calling Java APIs through `JNIEnv` rather than importing equivalent Windows APIs directly.

For that reason, JNI tracing became one of the primary methods used to reconstruct its behavior.

---

## License Flow

Once the Windows native engine had been extracted, the next objective was to locate the license implementation.

This was not immediately obvious from static analysis. The Java names are heavily obfuscated, most relevant methods contain no Java implementation, and the extracted native engine contains thousands of mostly anonymous functions.

The license path was therefore reconstructed progressively by correlating Java declarations, JNI native registration, runtime behavior, and native call sites.

### Identifying the License Object

The first useful clues came from inspecting the Java classes with `javap -p`.

Relevant declarations included:

```java
public static native void main(String[] args);
public static native a3 d();
public static native a3 e(int, int, char);

private a3(String, String, String);
```

This made `dev/jnic/a3` an early candidate for the license object.

There were several reasons for this.

Multiple native methods returned `a3`, indicating that it represented an object produced by the native engine rather than a simple Java utility.

More importantly, `a3` had a private constructor accepting three strings:

```text
(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
```

That structure was consistent with the license information displayed by JNIC during startup, which includes a license holder, expiry value, and edition.

At this point, however, `a3` was only a candidate. The Java declarations revealed the shape of the object but not what the native methods actually did.

### Mapping Java Methods to Native Code

The next problem was locating those Java methods inside the extracted Windows engine.

Because the native image contains thousands of functions without useful symbols, searching statically for a function named `a3.e` was not possible.

Instead, the JNI registration process was traced at runtime.

After detecting the temporary native engine load, the running Java VM was obtained through:

```text
JNI_GetCreatedJavaVMs
        ↓
JavaVM
        ↓
GetEnv
        ↓
JNIEnv
```

The `RegisterNatives` entry in the `JNIEnv` function table was then monitored.

Each `JNINativeMethod` record contains:

```text
method name
method signature
native implementation pointer
```

This produced a direct mapping between the obfuscated Java declarations and functions inside the native engine.

Relevant mappings included:

| Java method                     | Engine RVA |
| ------------------------------- | ---------: |
| `a3.e(IIC)Ldev/jnic/a3;`        | `0x4818d8` |
| `be.main([Ljava/lang/String;)V` | `0x44fae1` |
| `be.d()Ldev/jnic/a3;`           | `0x0f9604` |
| `a9.checkServerTrusted(...)V`   | `0x539d98` |

With the Windows image loaded at:

```text
0x180000000
```

the candidate `a3.e` implementation was therefore located at:

```text
RVA: 0x4818d8
VA:  0x1804818d8
```

This converted the Java-level hypothesis into a concrete native function that could be analyzed and traced.

### Confirming `a3` as the License Object

The next step was to establish whether `a3.e` was actually responsible for license processing.

Rather than attempting to completely decompile the native engine, selected JNI calls were traced and filtered by return addresses inside the JNIC module.

Particularly useful calls included:

```text
BufferedReader.readLine()
String.split(...)
MessageDigest.digest(...)
OutputStream.write(...)
CallObjectMethod(...)
CallVoidMethod(...)
CallIntMethod(...)
```

Following execution associated with the license path exposed behavior consistent with a license factory:

```text
open jnic.licence
        ↓
BufferedReader.readLine()
        ↓
split("/")
        ↓
native validation
        ↓
activation / license checking
        ↓
return dev/jnic/a3
```

Runtime tracing also exposed JNIC's lazily decrypted strings.

Relevant recovered values included:

```text
jnic.licence

https://activation.jnic.dev/api/activate
https://activation.jnic.dev/api/check?

token=
&app_id=
&machine=
&user=
&hwid=
&version=

Accept
Content-Type
application/json
SHA-256
```

Together, these observations established that `a3.e` was not simply an arbitrary function returning an `a3` instance. It was the factory responsible for making the license decision and returning the resulting license object.

### Recovering the `a3` Fields

The three constructor arguments were then correlated with the values displayed by JNIC.

The constructor is:

```text
(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
```

and represents:

```text
holder
expiry
edition
```

The first argument is displayed as the license holder, while the second is displayed as the expiry value.

The third string selects the license edition:

| Value | Displayed edition |
| ----- | ----------------- |
| `1`   | `standard`        |
| `2`   | `small developer` |
| `3`   | `evaluation`      |

For example, constructing:

```text
holder:  YumeCloud
expiry:  8888-88-88
edition: 1
```

produces:

```text
INFO: Licence: YumeCloud (standard)
INFO: Expires: 8888-88-88
```

This confirmed that `dev/jnic/a3` represents the license object and that its constructor contains the holder, expiry, and license edition used later by JNIC.

### Finding the Actual Call Path

Once `a3.e` had been identified, an obvious experiment was to replace its function pointer in the JNI registration table.

That replacement could be installed safely, but the license result did not change.

This indicated that the relevant invocation of `a3.e` was not going through normal JVM native-method dispatch.

Static analysis of the native `be.main` implementation revealed why.

At:

```text
0x180454801
```

`be.main` contains a direct call:

```asm
call sub_1804818D8
```

The actual license path is therefore:

```text
dev.jnic.be.main(...)
        ↓
native be.main
        ↓
direct native call
        ↓
a3.e @ 0x1804818d8
        ↓
license processing
        ↓
dev/jnic/a3
```

rather than:

```text
Java invocation
        ↓
JVM native dispatch
        ↓
RegisterNatives pointer
        ↓
a3.e
```

This explains why changing the registered JNI pointer was ineffective: the registration table identifies the implementation, but the native `be.main` code bypasses that table when performing the license check.

### Reconstructed License Path

At this stage, the overall execution path could be reconstructed as:

```text
JAR startup
    │
    ▼
JNICLoader
    │
    ├─ decompress embedded payload
    ├─ select platform-native image
    └─ System.load(...)
    │
    ▼
native initialization
    │
    ├─ JNI_OnLoad
    ├─ class-specific $jnicLoader routines
    ├─ RegisterNatives
    └─ integrity-sensitive initialization
    │
    ▼
be.main
    │
    ▼
direct call to a3.e
    │
    ├─ open jnic.licence
    ├─ read one line
    ├─ split on "/"
    ├─ perform native numeric validation
    ├─ derive machine information / HWID
    ├─ perform online checking when required
    └─ determine license result
    │
    ▼
dev/jnic/a3
    │
    ├─ holder
    ├─ expiry
    └─ edition
    │
    ▼
be.main continues
```

This also identified a useful interception point: if the factory could be replaced while preserving its return type, the remainder of JNIC could continue operating without requiring the original validation path to succeed.

### Finding the Correct Replacement Timing

The first attempts modified the factory immediately after the temporary native engine was loaded.

Those attempts caused repeatable JVM crashes during `be.$jnicLoader`.

The failing path eventually attempted a Java static call using a null or otherwise invalid class reference.

The observed behavior was approximately:

```text
engine loaded
    ↓
early native modification
    ↓
integrity-sensitive initialization disturbed
    ↓
internal class / string state becomes invalid
    ↓
JVM crash
```

The precise integrity algorithm was not completely isolated, but the timing and resulting failure were experimentally reproducible.

The next objective was therefore to find a point where:

```text
engine initialization          complete
class initialization           complete
integrity-sensitive work       complete
license factory call           not yet executed
```

A successful point was identified around the final startup banner emitted from `be.main`, associated with engine RVA:

```text
0x472bf6
```

Installing the replacement at this stage succeeded.

The final ordering therefore became:

```text
load native engine
        ↓
allow JNIC initialization to complete
        ↓
install factory replacement
        ↓
enter normal be.main execution
        ↓
direct a3.e call reaches replacement
```

This ordering is reproduced by the final launcher without requiring an external tracing session.

---

## License File

The original engine looks for:

```text
jnic.licence
```

The observed parser begins by reading a single line and splitting it on `/`:

```text
open jnic.licence
        ↓
BufferedReader.readLine()
        ↓
String.split("/")
        ↓
native numeric transformation
        ↓
comparison against embedded numeric data
        ↓
online checking
```

Format testing showed two clearly different outcomes.

A candidate shaped like:

```text
<24-character token>/<digit>
```

reached deeper validation and eventually produced:

```text
Licence validation failed: invalid key
```

while malformed inputs failed earlier with the generic file-open error.

Inputs tested in the latter category included missing suffixes, short numeric values, Base64-shaped values, and additional-line inputs.

This establishes the accepted parser shape, but does not demonstrate that a 24-character activation token alone is a complete valid offline license.

### Native Numeric Validation

The deeper validation path uses a 63-character zero-padding table and the native class `dev/jnic/ao`.

A recovered constant consists of 512 hexadecimal characters:

```text
512 hex characters
= 256 bytes
= 2048 bits
```

Its size and use are consistent with a public modulus used in an RSA-like numeric operation.

The available evidence supports that interpretation, but the exact exponent, padding scheme, and encoded message format were not fully recovered.

JNIC also contains an Ed25519 dependency. Its presence is confirmed, but its participation in this particular Windows license path was not established by the runtime trace.

---

## Activation Requests

Runtime tracing recovered the activation endpoint:

```text
POST https://activation.jnic.dev/api/activate
```

with:

```text
Accept: application/json
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
```

The request body follows:

```text
token=TOKEN24&app_id=3&machine=HOST&user=USER&hwid=HWID&version=3.7.0
```

The value after `/` in the license input is separated from the token and sent as `app_id`.

For example, the conceptual input:

```text
TOKEN24/3
```

becomes:

```text
token=TOKEN24
app_id=3
```

A failed activation request returned HTTP 404 with JSON containing fields including:

```text
error
result
support_message
```

A second endpoint observed during license checking begins with:

```text
GET https://activation.jnic.dev/api/check?
```

The exact `auth` serialization and server-side challenge calculation used by this request remain unresolved.

---

## HWID Generation

JNI tracing established how JNIC calculates the machine identifier used during activation.

The relevant Java operations are:

```text
InetAddress.getLocalHost()
        ↓
NetworkInterface.getByInetAddress(...)
        ↓
NetworkInterface.getHardwareAddress()
        ↓
SHA-256
        ↓
Base64
```

Conceptually:

```text
localAddress = InetAddress.getLocalHost()
interface    = NetworkInterface.getByInetAddress(localAddress)
mac          = interface.getHardwareAddress()

digest = SHA-256(mac)
hwid   = Base64(digest)
```

The digest input is the six raw MAC-address bytes returned by `getHardwareAddress()`.

The hostname is not part of this digest.

Instead:

```text
machine = local hostname
user    = System.getProperty("user.name")
hwid    = Base64(SHA-256(raw MAC))
```

These values are supplied separately in the activation request.

This corrected an earlier hypothesis that all network-interface names, MAC addresses, and the hostname were concatenated before hashing.

---

## TLS Public-Key Pinning

The recovered mapping:

```text
a9.checkServerTrusted(...)V
RVA: 0x539d98
```

led to JNIC's TLS verification path.

`dev/jnic/a9` implements `X509TrustManager`.

The server certificate is processed as:

```text
certificate.getPublicKey()
        ↓
PublicKey.getEncoded()
        ↓
SHA-256
        ↓
compare against embedded hash
```

`PublicKey.getEncoded()` returns the DER-encoded `SubjectPublicKeyInfo` structure.

The observed embedded value is:

```text
Base64:
o8A6OI58AOvUceqqKfs+TkfmCEubXzhYtXLi1ZWm3zI=

SHA-256:
a3c03a388e7c00ebd471eaaa29fb3e4e47e6084b9b5f3858b572e2d595a6df32
```

The certificate public key observed during analysis was RSA-2048.

JNIC therefore performs SHA-256 public-key pinning rather than using an accept-all trust manager.

---

## Runtime String Recovery

Many useful strings are not stored directly as readable plaintext in the native image.

JNIC decrypts strings lazily through a MethodHandle-based bootstrap mechanism.

JNI tracing exposed the following cryptographic sequence:

```text
Cipher.getInstance("DES/CBC/PKCS5Padding")
SecretKeyFactory.getInstance("DES")
Cipher.init(...)
Cipher.doFinal(...)
new String(..., "ISO-8859-1")
```

Capturing the byte arrays returned by `Cipher.doFinal` exposed plaintext strings as they were needed at runtime.

Recovered strings relevant to the license analysis included:

```text
jnic.licence

https://activation.jnic.dev/api/activate
https://activation.jnic.dev/api/check?

token=
&app_id=
&machine=
&user=
&hwid=
&version=

Accept
application/json

Content-Type
application/x-www-form-urlencoded; charset=UTF-8

SHA-256
```

This was particularly useful because it exposed the high-level operations surrounding otherwise heavily obfuscated native code.

---

## Modified Package

The final package changes the JAR entry point to:

```text
Main-Class: YumeCloud.Launcher
```

and contains:

```text
META-INF/MANIFEST.MF
YumeCloud/Launcher.class
YumeCloud/Patcher.class
YumeCloud/YumeCloud.dll
```

The launcher is responsible for reproducing the successful patch timing discovered during the dynamic analysis.

Its execution sequence is:

```text
YumeCloud.Launcher
        ↓
Class.forName("dev.jnic.be")
        ↓
JNIC initialization completes
        ↓
extract YumeCloud/YumeCloud.dll
        ↓
System.load(...)
        ↓
YumeCloud.Patcher.install()
        ↓
dev.jnic.be.main(args)
```

The important operation is:

```java
Class.forName("dev.jnic.be");
```

before the helper is installed.

This forces JNIC's class and native initialization to complete while the engine is still unmodified.

Only afterward is the runtime replacement installed.

---

## Runtime Replacement

`YumeCloud.dll` locates the temporary Windows engine loaded by `JNICLoader`.

The helper searches the loaded modules for the temporary engine and calculates the factory address using:

```text
factory = engine_base + 0x4818d8
```

It temporarily changes the target page protection and installs a 14-byte x64 absolute jump:

```text
48 B8 <eight-byte replacement address> FF E0 90 90
```

Conceptually, this changes:

```text
be.main
    ↓
a3.e
    ↓
original license processing
    ↓
a3 object / failure
```

into:

```text
be.main
    ↓
a3.e entry
    ↓
replacement factory
    ↓
construct dev/jnic/a3
    ↓
return object
```

### Replacement Factory

The replacement preserves the return type expected by the original native code.

Using JNI, it performs the equivalent of:

```text
FindClass("dev/jnic/a3")

GetMethodID(
    "<init>",
    "(String,String,String)V"
)

NewStringUTF("YumeCloud")
NewStringUTF("8888-88-88")
NewStringUTF("1")

NewObject(...)

return object
```

The resulting object is a real:

```text
dev/jnic/a3
```

instance containing:

```text
holder  = YumeCloud
expiry  = 8888-88-88
edition = 1 (standard)
```

JNIC therefore displays:

```text
INFO: Licence: YumeCloud (standard)
INFO: Expires: 8888-88-88
```

The other observed edition values are:

```text
1 -> standard
2 -> small developer
3 -> evaluation
```

From the perspective of the remainder of `be.main`, the factory returned the Java type and metadata it expected.

Execution therefore continues through the normal license display and compiler-discovery code rather than terminating at the original license failure.

### Why the Engine Is Not Prepatched

A simpler approach would have been to modify the extracted Windows native image permanently and package that modified image back into the JAR.

Testing showed that modifying the engine before its startup initialization completed caused the integrity-sensitive failure described earlier.

The final package is therefore better described as:

```text
self-contained JAR
        +
embedded native helper
        +
post-initialization runtime modification
```

The original embedded engine is allowed to initialize normally before its license factory is changed in memory.

No external Frida or Python process is required during normal execution.

---

## Analysis Method

The investigation used a combination of static and dynamic techniques rather than relying on a complete native decompilation.

The main process was:

```text
JAR inspection
        ↓
Java class inspection
        ↓
embedded payload identification
        ↓
LZMA2 decompression
        ↓
Windows PE extraction
        ↓
IDA analysis
        ↓
RegisterNatives tracing
        ↓
JNI API tracing
        ↓
runtime experiments
        ↓
license factory identification
        ↓
patch-timing experiments
```

The historical dynamic analysis used Frida 17.17.0 with Java 17.

The particularly useful tracing sequence was:

```text
LoadLibrary* hook
        ↓
JNI_GetCreatedJavaVMs
        ↓
JavaVM::GetEnv
        ↓
JNIEnv table
        ↓
RegisterNatives
        ↓
selected Java API calls
```

Useful trace points included:

```text
RegisterNatives
GetMethodID
GetStaticMethodID
CallObjectMethod
CallVoidMethod
CallIntMethod
OutputStream.write
MessageDigest.digest
BufferedReader.readLine
```

This approach allowed high-level Java operations to be correlated with execution inside otherwise anonymous native functions.

It was especially useful for recovering the license-file parser, activation request, HWID calculation, string decryption, TLS verification, and the fields contained by the `a3` license object.

---

## Limitations

This analysis and the modified package apply specifically to:

```text
JNIC 3.7.0
Windows x64
Java 17
```

The factory RVA:

```text
0x4818d8
```

belongs to the analyzed JNIC 3.7.0 Windows x64 engine.

A different JNIC version may change the engine layout, function implementation, initialization behavior, or ABI and should not be expected to work with the same address.

Several aspects of the original license implementation remain unresolved:

* the exact exponent and padding used by the apparent 2048-bit numeric validation
* the exact encoded message structure of that validation
* the complete `/api/check` query and `auth` calculation
* whether the bundled Ed25519 implementation participates in this license path

The replacement currently supplies:

```text
8888-88-88
```

as the expiry value.

This value is accepted and displayed by the tested startup path, but it is not a valid calendar date. A separate code path that strictly parses the value as a date could therefore behave differently.

The helper also modifies executable memory at runtime. Security software, a different Java runtime, or changes to the native engine may prevent the package from behaving as tested.

---

## Summary

JNIC 3.7.0 implements most of its functionality inside a compressed multi-platform native engine embedded in the JAR.

The embedded resource decompresses to **32,608,048 bytes**. On Windows x64, `JNICLoader` selects bytes `[0, 7,558,656)`, writes the resulting PE32+ image to a temporary file, and loads it through `System.load`.

The license investigation began with the Java declarations. The return type and three-string constructor made `dev/jnic/a3` a candidate license object. Runtime `RegisterNatives` tracing then mapped `a3.e(IIC)Ldev/jnic/a3;` to engine RVA `0x4818d8`.

JNI tracing associated that function with `jnic.licence` parsing, native validation, activation, and creation of the resulting `a3` object. Further testing established that the object's three constructor strings represent the license holder, expiry, and edition.

Static analysis then showed that native `be.main` calls `a3.e` directly, explaining why changing its JNI registration alone does not alter the license decision.

The original license system reads a slash-separated license value, performs additional native numeric validation, derives the HWID as `Base64(SHA-256(raw MAC))`, communicates with JNIC's activation service, and verifies the server using SHA-256 public-key pinning.

Runtime experiments further showed that modifying the engine immediately after loading interferes with its integrity-sensitive initialization. Replacing the factory after initialization, but before the direct license call, avoids that behavior.

`jnic-3.7.0-YumeCloud.jar` packages this result into a self-contained Windows x64 JAR. Its launcher first allows JNIC to initialize normally, then loads an embedded helper that redirects the native license factory and constructs:

```text
holder  = YumeCloud
expiry  = 8888-88-88
edition = 1 (standard)
```

The original `be.main` therefore receives the expected `dev/jnic/a3` object and reports:

```text
INFO: Licence: YumeCloud (standard)
INFO: Expires: 8888-88-88
```

without requiring an external Frida or Python session during normal execution.
