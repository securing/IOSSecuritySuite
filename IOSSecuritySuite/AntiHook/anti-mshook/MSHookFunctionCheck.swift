//
//  MSHookFunctionCheck.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/22.
//  Copyright © 2020 wregula. All rights reserved.
//

// LINK: https://github.com/TannerJin/AntiMSHookFunction

import Foundation

@inline(__always)
@_cdecl("msHookFunctionCheck")   // support Swift, OC
public func msHookFunctionCheck(_ function_addr: UnsafeMutableRawPointer) -> Bool {
    let arms = function_addr.assumingMemoryBound(to: UInt32.self)
    
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
