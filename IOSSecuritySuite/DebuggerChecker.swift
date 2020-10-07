//
//  DebuggerChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
//swiftlint:disable line_length

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
    
#if arch(arm64)
    static func hasBreakpointAt(_ functionAddr: UnsafeRawPointer, functionSize: vm_size_t?) -> Bool {
        let funcAddr = vm_address_t(UInt(bitPattern: functionAddr))
        
        var vmStart: vm_address_t = funcAddr
        var vmSize: vm_size_t = 0
        let vmRegionInfo = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<vm_region_basic_info_64>.size/4)
        defer {
            vmRegionInfo.deallocate()
        }
        var vmRegionInfoCount: mach_msg_type_number_t = mach_msg_type_number_t(VM_REGION_BASIC_INFO_64)
        var objectName: mach_port_t = 0
        
        let ret = vm_region_64(mach_task_self_, &vmStart, &vmSize, VM_REGION_BASIC_INFO_64, vmRegionInfo, &vmRegionInfoCount, &objectName)
        if ret != KERN_SUCCESS {
            return false
        }
        
        let vmRegion = vmRegionInfo.withMemoryRebound(to: vm_region_basic_info_64.self, capacity: 1, { $0 })
        
        if vmRegion.pointee.protection == (VM_PROT_READ | VM_PROT_EXECUTE) {
            let armBreakpointOpcode = 0xe7ffdefe
            let arm64BreakpointOpcode = 0xd4200000
            let instructionBegin = functionAddr.bindMemory(to: UInt32.self, capacity: 1)
            var judgeSize = (vmSize - (funcAddr - vmStart))
            if let size = functionSize, size < judgeSize {
                judgeSize = size
            }
            
            for valueToOffset in 0..<(judgeSize / 4) {
                if (instructionBegin.advanced(by: Int(valueToOffset)).pointee == armBreakpointOpcode) || (instructionBegin.advanced(by: Int(valueToOffset)).pointee == arm64BreakpointOpcode) {
                    return true
                }
            }
        }
        
        return false
    }
#endif

}
