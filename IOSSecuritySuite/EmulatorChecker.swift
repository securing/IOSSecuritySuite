//
//  EmulatorChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation

class EmulatorChecker {
    
    static func amIRunInEmulator() -> Bool {
        // NOTE: brackets are not needed here, the same with `self` keywords
        return (self.checkCompile() || self.checkRuntime())
    }
    
    private static func checkRuntime() -> Bool {
        
        // NOTE: there's no need of using `if` here, you could simply return the condition :)
        if ProcessInfo().environment["SIMULATOR_DEVICE_NAME"] != nil {
            return true
        }
        return false
    }
    
    // NOTE: That's the way we check if something is run on simulators :) 👍
    private static func checkCompile() -> Bool {
        
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
}
