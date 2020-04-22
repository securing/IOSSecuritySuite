//
//  AntiMSHookFunction.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/22.
//  Copyright © 2020 wregula. All rights reserved.
//

// LINK: https://github.com/TannerJin/AntiMSHookFunction

import Foundation

/// AntiMsHookFunction
/// - Parameter function_addr: checked function addr
/// - Returns: nil :   not been mshook
///            not nil : the right function addr after been mshook
@inline(__always)
@_cdecl("antiMsHookFunction")     // support Swift, OC
public func antiMsHookFunction(_ function_addr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
    if !msHookFunctionCheck(function_addr) {
        return nil
    }
    
    // 16: size of replaced instructions
    let function_begin = function_addr + 16
    
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
                    _func_begin.pointee == function_begin {
                    
                    return UnsafeMutableRawPointer(bitPattern: Int(vm_region_address))
                }
                
                // mshook handle `pc` offset
                /// 20:  max_buffer_instructions_count
                for i in 0..<20 {
                    if let instruction_addr = UnsafeMutablePointer<UnsafeMutableRawPointer>(bitPattern: Int(vm_region_address) + i * 4),
                        msHookFunctionCheck(instruction_addr) &&
                        (instruction_addr + 1).pointee == function_begin {
                        
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
