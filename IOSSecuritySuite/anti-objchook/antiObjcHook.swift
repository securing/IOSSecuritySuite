//
//  antiObjcHook.swift
//  RunLoop
//
//  Created by jintao on 2020/4/22.
//  Copyright © 2020 jintao. All rights reserved.
//

import Foundation
import MachO

//  *************************** Runtime Hook检测 *************************

// 动态加载dladdr函数，防止dladdr符号指针被fishhook替换
public typealias Dladdr = @convention(c) (UnsafeRawPointer, UnsafeMutablePointer<Dl_info>) -> Int

public var hookDladdr: Dladdr {
    let handle = dlopen("/usr/lib/libdl.dylib", RTLD_NOW)
    defer {
        dlclose(handle)
    }
    let sym = dlsym(handle, "dladdr")
    return unsafeBitCast(sym, to: Dladdr.self)
}

/// msg_send 检测消息机制的函数是否在其他dyld中(函数是否被交换到其他的注入的dyld中)
///
/// - Parameters:
///   - whiteListDylds: dylds of self app;   eg: ["UIKit", "Alamofire", "Kingfisher", "SwiftyJSONs"]
///   - detectionClassName: Swift: "Module.className"; OC: "className"
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

    // 函数指针imp
    let imp = method_getImplementation(method!)
    var info = Dl_info()

    if hookDladdr(UnsafeRawPointer(imp), &info) < 0 {
        // 未获取到imp信息
        return false
    }

    // imp的dyld的路径
    let impDyldPath = String(cString: info.dli_fname)

    // imp是否在系统库中
    if impDyldPath.contains("/System/Library/Frameworks") {
        return false
    }

    // imp是否在二进制中
    let binaryPath = String(cString: _dyld_get_image_name(0))
    if impDyldPath.contains(binaryPath) {
        return false
    }

    // imp是否在动态库的白名单中
    if let impFramework = impDyldPath.components(separatedBy: "/").last {
        return !whiteListDylds.contains(impFramework)
    }

    // 如果都不在, 即imp在注入的dyld中
    return true
}

