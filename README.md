# WiFi passphrase patch for CPLAY2air/Carlinkit

[CPLAY2air](https://cplay2air.com/) is a USB dongle that converts wired [CarPlay](https://www.apple.com/ios/carplay/) to wireless by acting as a proxy between a car and an iPhone. However, the [security posture](https://docs.google.com/document/d/13djB4hcYPSqWtYX6pC6erC3m3CR-QAWVGmP-5J-H6VI/pub#h.pgtwilhy0bqx) of the device is not great at all. The device creates a WiFi network with a static and poor passphrase `12345678`. Also, the device exposes an unauthenticated web interface, which can be used for firmware updates. In addition to all this madness, the firmware update process does not correctly validate the integrity of the uploaded file, as [ludwig-v](https://github.com/ludwig-v) has [shown](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering).

These vulnerabilities expose the device and the car to unnecessary risk since an attacker could too easily connect to the dongle and replace the stock firmware. This attack also gives the attacker easy access to the car's USB port that is usually a [great starting point](https://hitcon.org/2018/CMT/slide-files/d2_s0_r0_keynote.pdf) for compromising the infotainment system.

This patch allows you to change the non-secure default password of your choice, which reduces the risk of being compromised. However, I am not convinced should anyone use this device even with this patch.

## Requirements

A CPLAY2air/Carlinkit dongle running ludwig-v's [custom firmware](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/tree/master/Custom_Firmware). At the moment, the only supported version is `2021.03.06`.

If you are running a different version, check if the FW image contains the same version of the `/usr/sbin/ARMiPhoneIAP2` binary: `sha1:92d16ccb53d2e74ff4e7512bc78ecc851d72b189 `. If the same binary is used, then this patch should work directly without any modification. Otherwise you have to build a new version of the patch with the correct address of the passshrase location.

## Installation

1. Copy `inject.o`, `proxy.sh` and `U2W.sh` to a USB stick
   * `inject.o`: The patch which overwrites the default password.
   * `proxy.sh`: The shell script which loads the patch.
   * `U2W.sh`: The installer script.
2. Modify the value of the `PASSPHRASE` variable in `U2W.sh` to contain the new password. **Note: The password has to be exactly 8 characters.**
3. Connect the CPLAY2air/Carlinkit device to a power outlet and wait for it is booting
4. Connect the USB stick to the device and wait 10 seconds
5. Unplug the USB stick and reboot the device

## How does this work?

Before we can answer that question, we have to understand how CarPlay pairing works. During the initial pairing phase, iPhone and a car establish a Bluetooth link for creating an iAP2 session for exchanging the WiFi credentials. After the WiFi configuration details are transferred, iPhone uses them to connect to the car. You can read more information about this from [Apple's documentation](https://github.com/45clouds/WirelessCarPlay/blob/master/carplay.pdf).

The device leverages a [hostapd](https://w1.fi/hostapd/) daemon to create the wireless access point. The passphrase is configured with its config file located `/etc/hostpad.conf`, and the example config could be reviewed [here](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/blob/master/Extracted/2021.03.09.0001/rootfs/etc/hostapd.conf). Modifying the config file is easy. However, this is just the first half of the puzzle. The `/usr/sbin/ARMiPhoneIAP2` binary is used to transfer the WiFi credentials to the phone. However, the default `12345678` password is hard-coded to the binary.

The `ARMiPhoneIAP2` binary leverages an unidentified ELF binary packer that uses at least two decryption or compression layers to hide its actual functionality. To avoid reverse engineering all this maddness, runtime patching is applied. The binary is replaced by a shell script that executes the original binary and uses `LD_PRELOAD` functionality to load a shared library into the process, which changes the hardcoded passphrase before the credentials exchange happens. 

## Let's find the address of a passphrase

This section contains documentation on how to obtain the memory address of the passphrase. You require  [SSH access](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/tree/master/Custom_Firmware/Scripts/Dropbear) to the dongle, and the [toolchain](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/blob/master/Custom_Firmware/Scripts/Dropbear/NOTES.md) to build binaries (`strace`, `gdbserver`, etc.) for the device.

Before we can patch the passphrase, we have to locate the memory location of it. First, let's find some point of execution when the packer has done its magic, and the actual application is running. Based on the `strace` output, the first `brk` syscall happens between the execution of the packer and the actual binary, as shown below.

```bash
execve("/usr/sbin/ARMiPhoneIAP2", ["/usr/sbin/ARMiPhoneIAP2"], 0x7ea19dd0 /* 14 vars */) = 0
open("/proc/self/exe", O_RDONLY)        = 3
mmap2(NULL, 161136, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x76faf000
mmap2(0x76faf000, 158499, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, 3, 0) = 0x76faf000
cacheflush(0x76fd53a4, 0x76fd6570, 0)   = 0
mprotect(0x76fd4000, 9584, PROT_READ|PROT_EXEC) = 0
readlink("/proc/self/exe", "/usr/sbin/ARMiPhoneIAP2", 4095) = 23
cacheflush(0x7ed4638c, 0x7ed464c0, 0)   = 0
mmap2(0x10000, 458752, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x10000
mmap2(0x10000, 388788, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x10000
cacheflush(0x10000, 0x10134, 0)         = 0
mmap2(NULL, 153570, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x76f89000
open("/dev/hwaes", O_RDWR)              = 4
ioctl(4, _IOC(_IOC_READ|_IOC_WRITE, 0x62, 0x6, 0xc), 0x7ed46280) = 0
close(4)                                = 0
munmap(0x76f89000, 152546)              = 0
cacheflush(0x10134, 0x6eeb4, 0)         = 0
cacheflush(0x6eeb4, 0x6eebc, 0)         = 0
mprotect(0x10000, 388788, PROT_READ|PROT_EXEC) = 0
mmap2(0x7f000, 2752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f000
cacheflush(0x7f000, 0x7fac0, 0)         = 0
mprotect(0x7f000, 2752, PROT_READ|PROT_WRITE) = 0

brk(0x80000)                            = 0xcbc000 <---- The first brk syscall

open("/lib/ld-linux.so.3", O_RDONLY)    = 4
read(4, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0(\0\1\0\0\0\340\n\0\0004\0\0\0"..., 512) = 512
mmap2(NULL, 200704, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x76f7e000
mmap2(0x76f7e000, 126600, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED, 4, 0) = 0x76f7e000
mmap2(0x76fad000, 6272, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, 4, 0x1f000) = 0x76fad000
close(4)                                = 0
mmap2(NULL, 4096, PROT_READ, MAP_PRIVATE, 3, 0) = 0x76f7d000
close(3)                                = 0
munmap(0x76faf000, 161136)              = 0
brk(NULL)                               = 0xcbc000
uname({sysname="Linux", nodename="sk_mainboard", ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x76fd6000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/tmp/lib/tls/v7l/neon/vfp/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat64("/tmp/lib/tls/v7l/neon/vfp", 0x7ed46468) = -1 ENOENT (No such file or directory)
open("/tmp/lib/tls/v7l/neon/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat64("/tmp/lib/tls/v7l/neon", 0x7ed46468) = -1 ENOENT (No such file or directory)
```

Let's use `gdbserver` and `gdb` to do remote debugging and catch the syscall.

```bash
$ /mnt/UPAN/gdbserver-static 0.0.0.0:1337 /usr/sbin/ARMiPhoneIAP2
Process /usr/sbin/ARMiPhoneIAP2 created; pid = 268
Listening on port 1337
```

```bash
$ gdb-multiarch
pwndbg> target remote 192.168.50.2:1337
Remote debugging using 192.168.50.2:1337

pwndbg> catch syscall brk
Catchpoint 2 (syscall 'brk' [45])

pwndbg> info proc mappings
process 268
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	   0x10000    0x37000    0x27000        0x0 /usr/sbin/ARMiPhoneIAP2
	   0x40000    0x80000    0x40000        0x0 [heap]
	0x76fff000 0x77000000     0x1000        0x0 [sigpage]
	0x7efdf000 0x7f000000    0x21000        0x0 [stack]
	0xffff0000 0xffff1000     0x1000        0x0 [vectors]

pwndbg> c
Continuing.

Catchpoint 1 (call to syscall brk), 0x76ffd63c in ?? ()

pwndbg> info proc mappings
process 268
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	   0x10000    0x6f000    0x5f000        0x0  			<------- The text section of ARMiPhoneIAP2 have been changed
	   0x6f000    0x7f000    0x10000        0x0 
	   0x7f000    0x80000     0x1000        0x0 [heap]
	0x76fd7000 0x76ffc000    0x25000        0x0 /usr/sbin/ARMiPhoneIAP2
	0x76ffc000 0x76ffe000     0x2000    0x25000 /usr/sbin/ARMiPhoneIAP2
	0x76ffe000 0x76fff000     0x1000        0x0 
	0x76fff000 0x77000000     0x1000        0x0 [sigpage]
	0x7efdf000 0x7f000000    0x21000        0x0 [stack]
	0xffff0000 0xffff1000     0x1000        0x0 [vectors]

pwndbg> dump memory ~/code.dmp 0x10000 0x6f000
```

As shown in the above output, the packer replaced the content of the original text section (`0x1000`), and we can definitely spot the default password from a strings of the dump.

```bash
$ string code.dmp
<...snipped...>
AskStartPowerStateItems
iAP2PowerEngine
N21CiAP2WiFiConfigEngine5ItemsE
12345678
21CiAP2WiFiConfigEngine
/etc/wifi_name
set wifi ssid name: %s
WIFISSID
<...snipped...>
```

The relative address of the passphrase is `0x4f580` as show below, and a help of math we are able to figure out the absolute path: `0x10000 + 0x4f580 = 0x5f580`.

```bash
$ xxd code.dmp
<...snipped...>
0004f570: 5f95 0100 3577 0100 cf8f 0100 c97a 0100  _...5w.......z..
0004f580: 3132 3334 3536 3738 0000 0000 0000 0000  12345678........
0004f590: 0000 0000 c8f5 0500 7508 0200 8d08 0200  ........u.......
0004f5a0: 8905 0200 31be 0100 5905 0200 0032 3143  ....1...Y....21C
0004f5b0: 6941 5032 5769 4669 436f 6e66 6967 456e  iAP2WiFiConfigEn
0004f5c0: 6769 6e65 0000 0000 20fb 0700 adf5 0500  gine.... .......
0004f5d0: f4d2 0500 0000 0000 2f65 7463 2f77 6966  ......../etc/wif
0004f5e0: 695f 6e61 6d65 0073 6574 2077 6966 6920  i_name.set wifi 
0004f5f0: 7373 6964 206e 616d 653a 2025 730a 0057  ssid name: %s..W
0004f600: 4946 4953 5349 4400 7061 7373 5068 7261  IFISSID.passPhra
<...snipped...>
```

## Debugging

The patch can be executed manually over SSH to examine the debug information.

```bash
$ LD_PRELOAD=/usr/lib/inject.o /usr/sbin/ARMiPhoneIAP2_org

[+] Inject.so Loaded!
[*] PID: 223
[*] Process: /usr/sbin/ARMiPhoneIAP2_org
[+] Original value:
31 32 33 34 35 36 37 38  00 00 00 00 00 00 00 00  |  12345678........
[+] Password patched!
[+] Patched value:
63 68 61 6e 67 65 6d 65  00 00 00 00 00 00 00 00  |  changeme........
Usage: /usr/sbin/ARMiPhoneIAP2_org width height frameRate
```

