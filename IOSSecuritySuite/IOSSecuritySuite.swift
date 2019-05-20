//
//  IOSSecuritySuite.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation

// NOTE: By declaring class as open you allow the class to be subclassed within other modules. I assume we don't want that?
// Also let's be strict and unify this - if you declare methods as public, the class should be public as well.
// 👏 for nice documentation
open class IOSSecuritySuite {
    
    /**
     This type method is used to determine the true/false jailbreak status
     
     Usage example
     ```
     let isDeviceJailbroken = IOSSecuritySuite.amIJailbroken() ? true : false
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
     This type method is used to determine if application is run in emulator
     
     Usage example
     ```
     let runInEmulator = IOSSecuritySuite.amIRunInEmulator() ? true : false
     ```
     */
    public static func amIRunInEmulator() -> Bool {
        return EmulatorChecker.amIRunInEmulator()
    }
    
    /**
     This type method is used to determine if application is being debugged
     
     Usage example
     ```
     let amIDebugged = IOSSecuritySuite.amIDebugged() ? true : false
     ```
     */
    public static func amIDebugged() -> Bool {
        return DebuggerChecker.amIDebugged()
    }
    
    /**
     This type method is used to determine if there are any popular reverse engineering tools installed on the device
     
     Usage example
     ```
     let amIReverseEngineered = IOSSecuritySuite.amIReverseEngineered() ? true : false
     ```
     */
    public static func amIReverseEngineered() -> Bool {
        return ReverseEngineeringToolsChecker.amIReverseEngineered()
    }
}
