//
//  IOSSecuritySuite.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
// swiftlint:disable line_length trailing_whitespace

import Foundation
import MachO

@available(iOSApplicationExtension, unavailable)
public class IOSSecuritySuite {

    /**
     This type method is used to determine the true/false jailbreak status
     
     Usage example
     ```
     let isDeviceJailbroken: Bool = IOSSecuritySuite.amIJailbroken()
     ```
     */
    public static func amIJailbroken() -> Bool {
        return JailbreakChecker.amIJailbroken()
    }

    /**
     This type method is used to determine the jailbreak status with a message which jailbreak indicator was detected
     
     Usage example
     ```
     let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
     if jailbreakStatus.jailbroken {
     print("This device is jailbroken")
     print("Because: \(jailbreakStatus.failMessage)")
     } else {
     print("This device is not jailbroken")
     }
     ```
     
     - Returns: Tuple with with the jailbreak status *Bool* labeled *jailbroken* and *String* labeled *failMessage*
     to determine check that failed
     */
    public static func amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String) {
        return JailbreakChecker.amIJailbrokenWithFailMessage()
    }

    /**
    This type method is used to determine the jailbreak status with a list of failed checks

     Usage example
     ```
     let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
     if jailbreakStatus.jailbroken {
     print("This device is jailbroken")
     print("The following checks failed: \(jailbreakStatus.failedChecks)")
     }
     ```

     - Returns: Tuple with with the jailbreak status *Bool* labeled *jailbroken* and *[FailedCheck]* labeled *failedChecks*
     for the list of failed checks
     */
    public static func amIJailbrokenWithFailedChecks() -> (jailbroken: Bool, failedChecks: [FailedCheckType]) {
        return JailbreakChecker.amIJailbrokenWithFailedChecks()
    }

    /**
     This type method is used to determine if application is run in emulator
     
     Usage example
     ```
     let runInEmulator: Bool = IOSSecuritySuite.amIRunInEmulator()
     ```
     */
    public static func amIRunInEmulator() -> Bool {
        return EmulatorChecker.amIRunInEmulator()
    }

    /**
     This type method is used to determine if application is being debugged
     
     Usage example
     ```
     let amIDebugged: Bool = IOSSecuritySuite.amIDebugged()
     ```
     */
    public static func amIDebugged() -> Bool {
        return DebuggerChecker.amIDebugged()
    }

    /**
     This type method is used to deny debugger and improve the application resillency
     
     Usage example
     ```
     IOSSecuritySuite.denyDebugger()
     ```
     */
    public static func denyDebugger() {
        return DebuggerChecker.denyDebugger()
    }
    
    /**
     This method is used to determine if application was launched by something
     other than LaunchD (i.e. the app was launched by a debugger)
     
     Usage example
     ```
     let isNotLaunchD: Bool = IOSSecuritySuite.isParentPidUnexpected()
     ```
     */
    public static func isParentPidUnexpected() -> Bool {
        return DebuggerChecker.isParentPidUnexpected()
    }
    
    /**
    This type method is used to determine if application has been tampered with
    
    Usage example
    ```
    if IOSSecuritySuite.amITampered([.bundleID("biz.securing.FrameworkClientApp"), .mobileProvision("your-mobile-provision-sha256-value")]).result {
        print("I have been Tampered.")
    }
    else {
        print("I have not been Tampered.")
    }
    ```
    
    - Parameter checks: The file Integrity checks you want
    - Returns: The file Integrity checker result
    */
    public static func amITampered(_ checks: [FileIntegrityCheck]) -> FileIntegrityCheckResult {
        return IntegrityChecker.amITampered(checks)
    }

    /**
     This type method is used to determine if there are any popular reverse engineering tools installed on the device
     
     Usage example
     ```
     let amIReverseEngineered: Bool = IOSSecuritySuite.amIReverseEngineered()
     ```
     */
    public static func amIReverseEngineered() -> Bool {
        return ReverseEngineeringToolsChecker.amIReverseEngineered()
    }
  
    /**
    This type method is used to determine the reverse engineered status with a list of failed checks

     Usage example
     ```
     let reStatus = IOSSecuritySuite.amIReverseEngineeredWithFailedChecks()
     if reStatus.reverseEngineered {
        print("This device has evidence of reverse engineering")
        print("The following checks failed: \(reStatus.failedChecks)")
     }
     ```

     - Returns: Tuple with with the reverse engineered status *Bool* labeled *reverseEngineered* and *[FailedCheck]* labeled *failedChecks*
     for the list of failed checks
     */
    public static func amIReverseEngineeredWithFailedChecks() -> (reverseEngineered: Bool, failedChecks: [FailedCheckType]) {
        return ReverseEngineeringToolsChecker.amIReverseEngineeredWithFailedChecks()
    }
      
    /**
    This type method is used to determine if `objc call` has been RuntimeHooked by for example `Flex`
     
    Usage example
    ```
     class SomeClass {
        @objc dynamic func someFunction() {
        }
     }
     
    let dylds = ["IOSSecuritySuite", ...]
     
    let amIRuntimeHook: Bool = amIRuntimeHook(dyldWhiteList: dylds, detectionClass: SomeClass.self, selector: #selector(SomeClass.someFunction), isClassMethod: false)
    ```
     */
    public static func amIRuntimeHooked(dyldWhiteList: [String], detectionClass: AnyClass, selector: Selector, isClassMethod: Bool) -> Bool {
        return RuntimeHookChecker.amIRuntimeHook(dyldWhiteList: dyldWhiteList, detectionClass: detectionClass, selector: selector, isClassMethod: isClassMethod)
    }
    
    /**
    This type method is used to determine if  HTTP proxy was set in the iOS Settings.
     
    Usage example
    ```
    let amIProxied: Bool = IOSSecuritySuite.amIProxied()
    ```
     */
    public static func amIProxied() -> Bool {
        return ProxyChecker.amIProxied()
    }
}

#if arch(arm64)
@available(iOSApplicationExtension, unavailable)
public extension IOSSecuritySuite {
    /**
    This type method is used to determine if `function_address` has been hooked by `MSHook`
    
    Usage example
    ```
    func denyDebugger() {
    }
     
    typealias FunctionType = @convention(thin) ()->()
    
    let func_denyDebugger: FunctionType = denyDebugger   // `: FunctionType` is must
    let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
    let amIMSHookFunction: Bool = amIMSHookFunction(func_addr)
    ```
    */
    static func amIMSHooked(_ functionAddress: UnsafeMutableRawPointer) -> Bool {
        return MSHookFunctionChecker.amIMSHooked(functionAddress)
    }
    
    /**
    This type method is used to get original `function_address` which has been hooked by  `MSHook`
    
    Usage example
    ```
    func denyDebugger(value: Int) {
    }
     
    typealias FunctionType = @convention(thin) (Int)->()
     
    let funcDenyDebugger: FunctionType = denyDebugger
    let funcAddr = unsafeBitCast(funcDenyDebugger, to: UnsafeMutableRawPointer.self)
     
    if let originalDenyDebugger = denyMSHook(funcAddr) {
        unsafeBitCast(originalDenyDebugger, to: FunctionType.self)(1337) //Call orignal function with 1337 as Int argument
    } else {
        denyDebugger()
    }
    ```
    */
    static func denyMSHook(_ functionAddress: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
        return MSHookFunctionChecker.denyMSHook(functionAddress)
    }
    
    /**
    This type method is used to rebind `symbol` which has been hooked by `fishhook`
     
    Usage example
    ```
    denySymbolHook("$s10Foundation5NSLogyySS_s7CVarArg_pdtF")   // Foudation's NSlog of Swift
    NSLog("Hello Symbol Hook")
     
    denySymbolHook("abort")
    abort()
    ```
     */
    static func denySymbolHook(_ symbol: String) {
        FishHookChecker.denyFishHook(symbol)
    }
    
    /**
    This type method is used to rebind `symbol` which has been hooked  at one of image by `fishhook`
     
    Usage example
    ```
    for i in 0..<_dyld_image_count() {
        if let imageName = _dyld_get_image_name(i) {
            let name = String(cString: imageName)
            if name.contains("IOSSecuritySuite"), let image = _dyld_get_image_header(i) {
                denySymbolHook("dlsym", at: image, imageSlide: _dyld_get_image_vmaddr_slide(i))
                break
            }
        }
    }
    ```
     */
    static func denySymbolHook(_ symbol: String, at image: UnsafePointer<mach_header>, imageSlide slide: Int) {
        FishHookChecker.denyFishHook(symbol, at: image, imageSlide: slide)
    }
    
    /**
     This type method is used to get the SHA256 hash value of the executable file in a specified image
     
     **Dylib only.** This means you should set Mach-O type as `Dynamic Library` in your *Build Settings*.
     
     Calculate the hash value of the `__TEXT.__text` data of the specified image Mach-O file.
     
     Usage example
     ```
     // Manually verify SHA256 hash value of a loaded dylib
     if let hashValue = IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")), hashValue == "6d8d460b9a4ee6c0f378e30f137cebaf2ce12bf31a2eef3729c36889158aa7fc" {
         print("I have not been Tampered.")
     }
     else {
         print("I have been Tampered.")
     }
     ```
     
     - Parameter target: The target image
     - Returns: A hash value of the executable file.
     */
    static func getMachOFileHashValue(_ target: IntegrityCheckerImageTarget = .default) -> String? {
        return IntegrityChecker.getMachOFileHashValue(target)
    }
    
    /**
     This type method is used to find all loaded dylibs in the specified image
     
     **Dylib only.** This means you should set Mach-O type as `Dynamic Library` in your *Build Settings*.
     
     Usage example
     ```
     if let loadedDylib = IOSSecuritySuite.findLoadedDylibs() {
         print("Loaded dylibs: \(loadedDylib)")
     }
     ```
    
     - Parameter target: The target image
     - Returns: An Array with all loaded dylib names
    */
    static func findLoadedDylibs(_ target: IntegrityCheckerImageTarget = .default) -> [String]? {
        return IntegrityChecker.findLoadedDylibs(target)
    }
    /**
    This type method is used to determine if there are any breakpoints at the function
    
    Usage example
    ```
    func denyDebugger() {
        // add a breakpoint at here to test
    }
     
    typealias FunctionType = @convention(thin) ()->()
    
    let func_denyDebugger: FunctionType = denyDebugger   // `: FunctionType` is a must
    let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
    let hasBreakpoint: Bool = IOSSecuritySuite.hasBreakpointAt(func_addr, functionSize: nil)
    ```
    */
    static func hasBreakpointAt(_ functionAddr: UnsafeRawPointer, functionSize: vm_size_t?) -> Bool {
        return DebuggerChecker.hasBreakpointAt(functionAddr, functionSize: functionSize)
    }
    
    static func hasWatchpoint() -> Bool {
        return DebuggerChecker.hasWatchpoint()
    }
 }
 #endif
