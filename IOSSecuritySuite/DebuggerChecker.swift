//
//  DebuggerChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation

internal class DebuggerChecker {

    // https://developer.apple.com/library/archive/qa/qa1361/_index.html
    static func amIDebugged() -> Bool {
        
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
