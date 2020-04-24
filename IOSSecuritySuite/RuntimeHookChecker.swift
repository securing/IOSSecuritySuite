//
//  RuntimeHookChecker.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/24.
//  Copyright © 2020 wregula. All rights reserved.
//

import Foundation
import MachO

internal class RuntimeHookChecker {
        
    static private let swift_once_denyFishHooK: Void = {
        FishHookChecker.denyFishHook("dladdr")
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
        
        _ = swift_once_denyFishHooK
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
