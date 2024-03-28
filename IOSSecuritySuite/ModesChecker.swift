//
//  ModesChecker.swift
//  IOSSecuritySuite
//
//  Created by Wojciech Reguła on 28/03/2024.
//  Copyright © 2024 wregula. All rights reserved.
//

import Foundation

internal class ModesChecker {
  
  static func amIInLockdownMode() -> Bool {
    return UserDefaults.standard.bool(forKey: "LDMGlobalEnabled")
  }
  
}
