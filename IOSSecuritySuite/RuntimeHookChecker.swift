//
//  RuntimeHookChecker.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/24.
//  Copyright © 2020 wregula. All rights reserved.
//

import Foundation
import MachO

/*
    dladdr will look for the vm range of allImages until find the vm range of an Image is contains The Ptr
    And return info of the Image
 */

internal class RuntimeHookChecker {
    
    static private let swiftOnceDenyFishHooK: Void = {
        #if arch(arm64)
        FishHookChecker.denyFishHook("dladdr")
        #endif
    }()
    
    static func amIRuntimeHook(dyldWhiteList: [String], detectionClass: AnyClass, selector: Selector, isClassMethod: Bool) -> Bool {
        var method: Method?
        if isClassMethod {
            method = class_getClassMethod(detectionClass, selector)
        } else {
            method = class_getInstanceMethod(detectionClass, selector)
        }
        
        if method == nil {
            // method not found
            return true
        }
        
        let imp = method_getImplementation(method!)
        var info = Dl_info()
        
        _ = swiftOnceDenyFishHooK
        if dladdr(UnsafeRawPointer(imp), &info) != 1 {
            return false
        }
        
        let impDyldPath = String(cString: info.dli_fname)
        
        // at system framework
        if impDyldPath.contains("/System/Library/Frameworks") {
            return false
        }

        // at binary of app
        let binaryPath = String(cString: _dyld_get_image_name(0))
        if impDyldPath.contains(binaryPath) {
            return false
        }

        // at whiteList 
        if let impFramework = impDyldPath.components(separatedBy: "/").last {
            return !dyldWhiteList.contains(impFramework)
        }
        
        // at injected framework
        return true
    }
}
