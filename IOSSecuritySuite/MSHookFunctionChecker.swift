//
//  MSHookFunctionCherker.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/24.
//  Copyright © 2020 wregula. All rights reserved.
//  https://github.com/TannerJin/AntiMSHookFunction

import Foundation

/*
Original:
 
    * original function address(just for example)
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
 |       1. vm_region_new is creaded by MSHookFunction and it's VM_PROT is VM_PROT_READ and VM_PROT_EXECUTE
 |
 |       2. at begion of vm_region_new, it store some instructions that can call original function
 |
 |       3. at begion of vm_region_new, it likes below instructions
 |           ...         (>= 16 bytes for arm64)        >=4 hooked instructions
 |           ldr x16 #8  (4 bytes for arm64)
 |           br x16      (4 bytes for arm64)
 *------     address     (8 bytes for arm64)            address = original_function_address + 16
 
 */

#if arch(arm64)
internal class MSHookFunctionChecker {
    
    static func amIMSHookFunction(_ functionAddr: UnsafeMutableRawPointer) -> Bool {
        let arms = functionAddr.assumingMemoryBound(to: UInt32.self)
        
        let firstInstruction = arms.pointee
        let secondInstruction = (arms + 1).pointee
        
        // firstInstruction
        let ldr = (firstInstruction & (7 << 25)) >> 25
        let x16 = firstInstruction & (31 << 0)
        
        let ldr_x16 = (ldr == 4 && x16 == 16)
        
        // secondInstruction
        let ldr_2 = (secondInstruction & (7 << 25)) >> 25
        let x15_2 = (secondInstruction & (15 << 16)) >> 16
        let x16_2 = (secondInstruction & (127 << 5)) >> 5
        
        let br_x16 = (ldr_2 == 3 && x15_2 == 15 && x16_2 == 16)
        
        return ldr_x16 && br_x16
    }
    
    static func denyMSHookFunction(_ functionAddr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
        if !amIMSHookFunction(functionAddr) {
            return nil
        }
        
        // 16: size of replaced instructions
        let functionBegin = functionAddr + 16
        
        // look up vm_region
        let vm_region_info = UnsafeMutablePointer<Int32>.allocate(capacity: MemoryLayout<vm_region_basic_info_64>.size/4)
        defer {
            vm_region_info.deallocate()
        }
        var vm_region_address: vm_address_t = 1
        var vm_region_size: vm_size_t = 0
        var vm_region_info_count: mach_msg_type_number_t = mach_msg_type_number_t(VM_REGION_BASIC_INFO_64)
        var object_name: mach_port_t = 0
        
        while true {
            if vm_region_address == 0 {
                return nil
            }
            let ret = vm_region_64(mach_task_self_, &vm_region_address, &vm_region_size, VM_REGION_BASIC_INFO_64, vm_region_info, &vm_region_info_count, &object_name)
            
            if ret == KERN_SUCCESS {
                let region_info = UnsafeMutableRawPointer(vm_region_info).assumingMemoryBound(to: vm_region_basic_info_64.self)
                
                // vm region of code
                if region_info.pointee.protection == (VM_PROT_READ|VM_PROT_EXECUTE) {
                    // mshook do not handle `pc` offset
                    if let _func_begin = UnsafeMutablePointer<UnsafeMutableRawPointer>(bitPattern: Int(vm_region_address) + 16 + 8),
                        _func_begin.pointee == functionBegin {
                        
                        return UnsafeMutableRawPointer(bitPattern: Int(vm_region_address))
                    }
                    
                    // mshook handle `pc` offset
                    /// 20:  max_buffer_instructions_count
                    for i in 0..<20 {
                        if let instruction_addr = UnsafeMutablePointer<UnsafeMutableRawPointer>(bitPattern: Int(vm_region_address) + i * 4),
                            amIMSHookFunction(instruction_addr) &&
                            (instruction_addr + 1).pointee == functionBegin {
                            
                            return UnsafeMutableRawPointer(bitPattern: Int(vm_region_address))
                        }
                    }
                }
                
                vm_region_address += vm_region_size
            } else {
                return nil
            }
        }
    }
}
#endif
