//
//  IOSSecuritySuite.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation

public class IOSSecuritySuite {

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
    public static func amIJailbrokenWithFailedChecks() -> (jailbroken: Bool, failedChecks: [FailedCheck]) {
        return JailbreakChecker.amIJailbrokenWithFailedChecks()
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
