//
//  MSHookFunctionCherker.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/24.
//  Modified by Ant-Tree on 2023/01/25.
//
//  Copyright © 2020 wregula. All rights reserved.
//  https://github.com/TannerJin/AntiMSHookFunction
// swiftlint:disable cyclomatic_complexity function_body_length trailing_whitespace

import Foundation

/*
Original:
 
    * original function address (example)
        stp x22, x21, [sp, #-0x10]
        stp x20, x19, [sp, #-0x20]
        stp x29, x30, [sp, #-0x30]
        .
        .
        .
 
    * vm_regions
    
         vm_region_0                         vm_region_n
        *-----------*                       *-----------*
        |           |                       |           |
        |           |  ----->  ...  ----->  |           |
        |           |  <-----       <-----  |           |
        *-----------*                       *-----------*
|
|
V
 
After MSHookFunction(mmap):
 
    * original function address
        ldr x16 #8  (4 bytes for arm64)
        br x16      (4 bytes for arm64)
        address     (8 bytes for arm64)  address = hook_function_address
 *->     .
 |       .
 |       .
 |
 |   * vm_regions
 |
 |       vm_region_0                         vm_region_new                       vm_region_n+1
 |       *-----------*                       *-----------*                       *-----------*
 |       |           |                       |           |                       |           |
 |       |           |  ----->  ...  ----->  |           |  ----->  ... ----->   |           |
 |       |           |  <-----       <-----  |           |  <-----      <-----   |           |
 |       *-----------*                       *-----------*                       *-----------*
 |
 |
 |       1. The vm_region_new is created by MSHookFunction with VM_PROT that is VM_PROT_READ and VM_PROT_EXECUTE
 |
 |       2. Instructions that can call original function are stored at the beginning of vm_region_new
 |
 |       3. The beginning of vm_region_new should look like instructions below
 |           ...         (>= 16 bytes for arm64)        >=4 hooked instructions
 |           ldr x16 #8  (4 bytes for arm64)
 |           br x16      (4 bytes for arm64)
 *------     address     (8 bytes for arm64)            address = original_function_address + 16
 
 (For Cydia Substrate, the code block above doesn't guaranteed to be at the beginning of a region)
 */

#if arch(arm64)
internal class MSHookFunctionChecker {
    // come from ARM® Architecture Reference Manual, ARMv8 for ARMv8-A architecture profile
    private enum MSHookInstruction {
        // swiftlint:disable identifier_name line_length
        case ldr_x16
        case br_x16
        case adrp_x17(pageBase: UInt64)
        case add_x17(pageOffset: UInt64)
        case br_x17
        
        @inline(__always)
        static fileprivate func translateInstruction(at functionAddr: UnsafeMutableRawPointer) -> MSHookInstruction? {
            let arm = functionAddr.assumingMemoryBound(to: UInt32.self).pointee
            // ldr xt, #imm  (C4.4.5 and C6.2.84)
            let ldr_register_litetal = (arm & (255 << 24)) >> 24
            if ldr_register_litetal == 0b01011000 {
                let rt = arm & 31
                let imm19 = (arm & ((1 << 19 - 1) << 5)) >> 5
                // ldr x16, #8
                if rt == 16 && (imm19 << 2) == 8 {
                    return ldr_x16
                }
            }
            // br
            let br = arm >> 10
            if br == 0b1101011000011111000000 {
                let br_rn = (arm & (31 << 5)) >> 5
                if br_rn == 16 {
                    return .br_x16
                }
                if br_rn == 17 {
                    return .br_x17
                }
            }
            // adrp (C6.2.10)
            let adrp_op = arm >> 31
            let adrp = (arm & (31 << 24)) >> 24
            let rd = arm & (31 << 0)
            if adrp_op == 1 && adrp == 16 {
                let pageBase = getAdrpPageBase(functionAddr)
                // adrp x17, pageBase
                if rd == 17 {
                    return .adrp_x17(pageBase: pageBase)
                }
            }
            // add (C4.2.1 and C6.2.4)
            let add = arm >> 24
            if add == 0b10010001 {      // 32-bit: 0b00010001
                let add_rn = (arm & (31 << 5)) >> 5
                let add_rd = arm & 31
                let add_imm12 = UInt32((arm & ((1 << 12-1) << 10)) >> 10)
                var imm = UInt64(add_imm12)
                let shift = (arm & (3 << 22)) >> 22
                if shift == 0 {
                    imm = UInt64(add_imm12)
                } else if shift == 1 {
                    imm = UInt64(add_imm12 << 12)
                } else {
                    // AArch64.UndefinedFault
                    return nil
                }
                // add x17, x17, add_im
                if add_rn == 17 && add_rd == 17 {
                    return .add_x17(pageOffset: imm)
                }
            }
            return nil
        }
        
        // pageBase
        @inline(__always)
        static private func getAdrpPageBase(_ functionAddr: UnsafeMutableRawPointer) -> UInt64 {
            let arm = functionAddr.assumingMemoryBound(to: UInt32.self).pointee
            func singExtend(_ value: Int64) -> Int64 {
                var result = value
                let sing = value >> (33-1) == 1
                if sing {
                    result = ((1<<31-1) << 33) | value
                }
                return result
            }
            // +/- 4GB
            let immlo = (arm >> 29) & 3
            let immhiMask = UInt32((1 << 19 - 1) << 5)
            let immhi = (arm & immhiMask) >> 5
            let imm = (Int64((immhi << 2 | immlo)) << 12)
            let pcBase = (UInt(bitPattern: functionAddr) >> 12) << 12
            return UInt64(Int64(pcBase) + singExtend(imm))
        }
    }
    
    @inline(__always)
    static func amIMSHooked(_ functionAddr: UnsafeMutableRawPointer) -> Bool {
        guard let firstInstruction = MSHookInstruction.translateInstruction(at: functionAddr) else {
            return false
        }
        switch firstInstruction {
        case .ldr_x16:
            let secondInstructionAddr = functionAddr + 4
            if case .br_x16 = MSHookInstruction.translateInstruction(at: secondInstructionAddr) {
                return true
            }
            return false
        case .adrp_x17:
            let secondInstructionAddr = functionAddr + 4
            let thridInstructionAddr = functionAddr + 8
            if case .add_x17 = MSHookInstruction.translateInstruction(at: secondInstructionAddr),
                case .br_x17 = MSHookInstruction.translateInstruction(at: thridInstructionAddr) {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    @inline(__always)
    static func denyMSHook(_ functionAddr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
        if !amIMSHooked(functionAddr) {
            return nil
        }
        // size of replaced instructions
        guard let firstInstruction = MSHookInstruction.translateInstruction(
            at: functionAddr
        ) else {
            assert(false, "amIMSHookFunction has judged")
            return nil
        }
        var origFunctionBeginAddr = functionAddr
        switch firstInstruction {
        case .ldr_x16:
            origFunctionBeginAddr += 16
        case .adrp_x17:
            origFunctionBeginAddr += 12
        default:
            assert(false, "amIMSHookFunction has judged")
            return nil
        }
        // look up vm_region
        let vmRegionInfo = UnsafeMutablePointer<Int32>.allocate(
            capacity: MemoryLayout<vm_region_basic_info_64>.size/4
        )
        defer {
            vmRegionInfo.deallocate()
        }
        var vmRegionAddress: vm_address_t = 1
        var vmRegionSize: vm_size_t = 0
        var vmRegionInfoCount: mach_msg_type_number_t = mach_msg_type_number_t(VM_REGION_BASIC_INFO_64)
        var objectName: mach_port_t = 0
        
        while true {
            if vmRegionAddress == 0 {
                // False address
                return nil
            }
            
            // Get VM region of designated address
            if vm_region_64(
                mach_task_self_,
                &vmRegionAddress,
                &vmRegionSize,
                VM_REGION_BASIC_INFO_64,
                vmRegionInfo,
                &vmRegionInfoCount,
                &objectName
            ) != KERN_SUCCESS {
                // End of vm_regions or something wrong
                return nil
            }
            
            let regionInfo = UnsafeMutableRawPointer(vmRegionInfo).assumingMemoryBound(
                to: vm_region_basic_info_64.self
            )
            
            // vm region of code
            if regionInfo.pointee.protection != (VM_PROT_READ|VM_PROT_EXECUTE) {
                // Memory protection level of executable region is always READ + EXECUTE
                vmRegionAddress += vmRegionSize
                continue
            }
            
            // ldr (Mobile Substrate)
            if case .ldr_x16 = firstInstruction {
                
                // Current vm region instruction address
                var vmRegionProcedureAddr = vmRegionAddress
                // Current vm region instruction address
                var vmRegionInstAddr = vmRegionAddress
                // Last address of current vm region
                let vmRegionEndAddress = vmRegionAddress + vmRegionSize
                
                // Unlike substitute, When using substrate, branching address may resides anywhere in vm region.
                // So every region must be investigated to check whether it contains original function address.
                while vmRegionEndAddress >= vmRegionInstAddr {
                    vmRegionInstAddr += 4
                    guard let instructionAddr = UnsafeMutablePointer<UnsafeMutableRawPointer>(
                        bitPattern: Int(vmRegionInstAddr)
                    ) else {
                        continue
                    }
                    
                    if UInt(bitPattern: instructionAddr.pointee) == 0 {
                        vmRegionProcedureAddr = vmRegionInstAddr + 4
                        continue
                    }
                    
                    if case .ldr_x16 = MSHookInstruction.translateInstruction(
                        at: instructionAddr
                    ), case .br_x16 = MSHookInstruction.translateInstruction(
                        at: UnsafeMutableRawPointer(instructionAddr) + 4
                    ), (instructionAddr + 1).pointee == origFunctionBeginAddr {
                        return UnsafeMutableRawPointer(
                            bitPattern: Int(vmRegionProcedureAddr + 4)
                        )
                    }
                }
            }
            // adrp (Substitute)
            if case .adrp_x17 = firstInstruction {
                // 20: max_buffer_insered_Instruction
                for i in 3..<20 {
                    if let instructionAddr = UnsafeMutableRawPointer(bitPattern: Int(vmRegionAddress) + i * 4),
                       case let .adrp_x17(pageBase: pageBase) = MSHookInstruction.translateInstruction(at: instructionAddr),
                       case let .add_x17(pageOffset: pageOffset) = MSHookInstruction.translateInstruction(at: instructionAddr + 4),
                       case .br_x17 = MSHookInstruction.translateInstruction(at: instructionAddr + 8),
                       pageBase+pageOffset == UInt(bitPattern: origFunctionBeginAddr) {
                        return UnsafeMutableRawPointer(bitPattern: Int(vmRegionAddress))
                    }
                }
            }
            vmRegionAddress += vmRegionSize
            
        }
    }
}
#endif
