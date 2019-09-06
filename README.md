![ISS logo](./logo.png)
### by @_r3ggi

## ISS Description
🌏 iOS Security Suite is an advanced and easy-to-use platform security & anti-tampering library written in pure Swift! If you are developing for iOS and you want to protect your app according to the OWASP [MASVS](https://github.com/OWASP/owasp-masvs) standard, chapter v8, then this library could save you a lot of time. 🚀

What ISS detects:

* Jailbreak (even the iOS 11+ with brand new indicators! 🔥)
* Attached debugger 👨🏻‍🚀
* If an app was run in emulator 👽
* Common reverse engineering tools running on the device 🔭

## Setup
There are 3 ways you can start using IOSSecuritySuite

### 1. Add source
Add `IOSSecuritySuite/*.swift` files to your project

### 2. Setup with CocoaPods
`pod 'IOSSecuritySuite'`

### 3. Setup with Carthage
`github "securing/IOSSecuritySuite"`

### Update Info.plist
After adding ISS to your project, you will also need to update your main Info.plist. There is a check in jailbreak detection module that uses ```canOpenURL(_:)``` method and [requires](https://developer.apple.com/documentation/uikit/uiapplication/1622952-canopenurl) specyfing URLs that will be queried.

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
	<string>cydia</string>
	<string>undecimus</string>
	<string>sileo</string>
</array>
```  

## How to use

### Jailbreak detector module

* This method returns a binary value of True/False if you just want to know if the device is jailbroken or jailed

```Swift
if IOSSecuritySuite.amIJailbroken() {
	print("This device is jailbroken")
} else {
	print("This device is not jailbroken")
}
```

* Verbose if you also want to know what indicators were identified

```Swift
let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
if jailbreakStatus.jailbroken {
	print("This device is jailbroken")
	print("Because: \(jailbreakStatus.failMessage)")
} else {
	print("This device is not jailbroken")
}
```
The failMessage is a String containing comma separated indicators as shown on the example below:
`Cydia URL scheme detected, Suspicious file exists: /Library/MobileSubstrate/MobileSubstrate.dylib, Fork was able to create a new process`

### Debbuger detector module
```Swift
let amIDebugged = IOSSecuritySuite.amIDebugged() ? true : false
```

### Deny debugger at all
```Swift
IOSSecuritySuite.denyDebugger()
```

### Emulator detector module
```Swift
let runInEmulator = IOSSecuritySuite.amIRunInEmulator() ? true : false
```

### Reverse engineering tools detector module
```Swift
let amIReverseEngineered = IOSSecuritySuite.amIReverseEngineered() ? true : false
```

## Security considerations
Before using this and other platform security checkers you have to understand that:

* Including this tool in your project is not the only thing you should do in order to improve your app security! You can read a general mobile security whitepaper [here](https://www.securing.biz/en/mobile-application-security-best-practices/index.html).
* Detecting if a device is jailbroken is done locally on the device. It means that every jailbreak detector may be bypassed (even this)! 
* Swift code is considered to be harder to manipulate dynamically than Objective-C. Since this library was written in pure Swift, the IOSSecuritySuite methods shouldn't be exposed to Objective-C runtime (which makes it more difficult to bypass ✅). You have to know that attacker is still able to MSHookFunction/MSFindSymbol Swift symbols and dynamically change Swift code execution flow.
* It's also a good idea to obfuscate the whole project code including this library. See [Swiftshield](https://github.com/rockbruno/swiftshield)

## Contribution ❤️
Yes, please! If you have a better idea or you just want to improve this project, please text me on [Twitter](https://twitter.com/_r3ggi) or [Linkedin](https://www.linkedin.com/in/wojciech-regula/). Pull requests are more than welcome!

### Special thanks: 👏🏻

* [kubajakowski](https://github.com/kubajakowski) for pointing out the problem with ```canOpenURL(_:)``` method
* [olbartek](https://github.com/olbartek) for code review and pull request 

## TODO
* [ ] File integrity checks

* [x] Deny debugger

## License
See the LICENSE file.

## References
While creating this tool I used:

* 🔗 https://github.com/TheSwiftyCoder/JailBreak-Detection
* 🔗 https://github.com/abhinashjain/jailbreakdetection 
* 🔗 https://gist.github.com/ddrccw/8412847
* 🔗 https://gist.github.com/bugaevc/4307eaf045e4b4264d8e395b5878a63b
* 📚 "iOS Application Security" by David Thiel