//
//  ProxyChecker.swift
//  IOSSecuritySuite
//
//  Created by Wojciech Reguła on 07/12/2020.
//  Copyright © 2020 wregula. All rights reserved.
//

import Foundation

internal class ProxyChecker {
    
    static func amIProxied() -> Bool {
        
        guard let unmanagedSettings = CFNetworkCopySystemProxySettings() else {
            return false
        }
        
        let settingsOptional = unmanagedSettings.takeRetainedValue() as? [String: Any]
        
        guard  let settings = settingsOptional else {
            return false
        }
               
        return (settings.keys.contains("HTTPProxy") || settings.keys.contains("HTTPSProxy"))
    }
}
