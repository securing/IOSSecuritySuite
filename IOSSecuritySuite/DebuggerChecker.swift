//
//  DebuggerChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation

class DebuggerChecker {
    
    static func amIDebugged() -> Bool {
        return self.checkDebugger()
    }

    // https://developer.apple.com/library/archive/qa/qa1361/_index.html
    // NOTE: as method is private it does not matter at all but generally this methods sounds like this does some action and returns nothing (Void)
    // when you want to be strict to Swift's naming conventions obviously a better name would be `amIDebugged()` as you proposed in public API
    //
    // Some Switf's naming conventions to look through (just in case :)):
    // https://swift.org/documentation/api-design-guidelines/
    // https://github.com/raywenderlich/swift-style-guide
    private static func checkDebugger() -> Bool {
        
        var kinfo = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let sysctlRet = sysctl(&mib, UInt32(mib.count), &kinfo, &size, nil, 0)

        if sysctlRet != 0 {
            print("Error occured when calling sysctl(). The debugger check may be not reliable")
        }
        
        return (kinfo.kp_proc.p_flag & P_TRACED) != 0
    }
    
}
