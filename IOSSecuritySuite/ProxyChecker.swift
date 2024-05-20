//
//  ProxyChecker.swift
//  IOSSecuritySuite
//
//  Created by Wojciech Reguła on 07/12/2020.
//  Copyright © 2020 wregula. All rights reserved.
//

import Foundation

internal class ProxyChecker {
    static func amIProxied(considerVPNConnectionAsProxy: Bool = false) -> Bool {
        guard let unmanagedSettings = CFNetworkCopySystemProxySettings() else {
            return false
        }
        
        let settingsOptional = unmanagedSettings.takeRetainedValue() as? [String: Any]
        
        guard  let settings = settingsOptional else {
            return false
        }
        
        if(considerVPNConnectionAsProxy) {
            if let scoped = settings["__SCOPED__"] as? [String: Any] {
                for interface in scoped.keys {
                    
                    let names = [
                        "tap",
                        "tun",
                        "ppp",
                        "ipsec",
                        "utun"
                    ]
                    
                    for name in names {
                        if(interface.contains(name)) {
                            print("detected: \(interface)")
                            return true
                        }
                    }
                }
            }
        }
        
        return (settings.keys.contains("HTTPProxy") || settings.keys.contains("HTTPSProxy"))
    }
}
