//
//  MacChecker.swift
//  IOSSecuritySuite
//
//  Created by bokuhe on 2022/11/18.
//  Copyright © 2022 wregula. All rights reserved.
//

import Foundation

internal class MacChecker {

    static func amIRunInMac() -> Bool {
        if #available(iOS 14.0, *) {
            return ProcessInfo.processInfo.isiOSAppOnMac
        } else {
            return false
        }
    }
}
