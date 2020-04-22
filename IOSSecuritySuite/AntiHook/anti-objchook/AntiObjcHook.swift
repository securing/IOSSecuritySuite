//
//  AntiObjcHook.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/22.
//  Copyright © 2020 jintao. All rights reserved.
//

import Foundation
import MachO

public typealias Dladdr = @convention(c) (UnsafeRawPointer, UnsafeMutablePointer<Dl_info>) -> Int

public var hookDladdr: Dladdr {
    let handle = dlopen("/usr/lib/libdl.dylib", RTLD_NOW)
    defer {
        dlclose(handle)
    }
    let sym = dlsym(handle, "dladdr")
    return unsafeBitCast(sym, to: Dladdr.self)
}

/// 
///
/// - Parameters:
///   - whiteListDylds: dylds of self app;   eg: ["UIKit", "Alamofire", "Kingfisher", "SwiftyJSONs"...]
///   - detectionClassName: Swift: "Module.className";    OC: "className"
///   - selector: Class's method
///   - isClassMethod: is Class method
/// - Returns: true: exchange; false: not exchange
@inline(__always)
public func hookRuntimeDetection(whiteListDylds: [String], className detectionClassName: String, selector: Selector, isClassMethod: Bool) -> Bool {
    guard let detectionClass = objc_getClass(detectionClassName) as? AnyClass else {
        print("class not found")
        return false
    }
    var method: Method?
    if isClassMethod {
        method = class_getClassMethod(detectionClass, selector)
    } else {
        method = class_getInstanceMethod(detectionClass, selector)
    }
    if method == nil {
        print("method of class not found")
        return false
    }

    // imp
    let imp = method_getImplementation(method!)
    var info = Dl_info()

    if hookDladdr(UnsafeRawPointer(imp), &info) < 0 {
        return false
    }

    // dyld path of imp
    let impDyldPath = String(cString: info.dli_fname)

    // at Library?
    if impDyldPath.contains("/System/Library/Frameworks") {
        return false
    }

    // at binary?
    let binaryPath = String(cString: _dyld_get_image_name(0))
    if impDyldPath.contains(binaryPath) {
        return false
    }

    // at whiteList?
    if let impFramework = impDyldPath.components(separatedBy: "/").last {
        return !whiteListDylds.contains(impFramework)
    }

    // at inserted dyld
    return true
}

