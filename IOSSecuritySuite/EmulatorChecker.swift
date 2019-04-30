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
        return (self.checkCompile() || self.checkRuntime())
    }
    
    private static func checkRuntime() -> Bool {
        
        if ProcessInfo().environment["SIMULATOR_DEVICE_NAME"] != nil {
            return true
        }
        return false
    }
    
    private static func checkCompile() -> Bool {
        
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
}
