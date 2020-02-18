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
            print("Error occured when calling sysctl(). The debugger check may not be reliable")
        }

        return (kinfo.kp_proc.p_flag & P_TRACED) != 0
    }

    static func denyDebugger() {

        // bind ptrace()
        let pointerToPtrace = UnsafeMutableRawPointer(bitPattern: -2)
        let ptracePtr = dlsym(pointerToPtrace, "ptrace")
        typealias PtraceType = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
        let ptrace = unsafeBitCast(ptracePtr, to: PtraceType.self)

        // PT_DENY_ATTACH == 31
        let ptraceRet = ptrace(31, 0, 0, 0)

        if ptraceRet != 0 {
            print("Error occured when calling ptrace(). Denying debugger may not be reliable")
        }
    }

}
