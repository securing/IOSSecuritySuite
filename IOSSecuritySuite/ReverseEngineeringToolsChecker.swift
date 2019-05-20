//
//  ReverseEngineeringToolsChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 24/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation
import MachO // dyld

class ReverseEngineeringToolsChecker {
    
    static func amIReverseEngineered() -> Bool {
        return (self.checkDYLD() || self.checkExistenceOfSuspiciousFiles() || self.checkOpenPorts())
    }
    
    private static func checkDYLD() -> Bool {
        
        let suspiciousLibraries = [
            "FridaGadget",
            "frida", // Needle injects frida-somerandom.dylib
            "cynject",
            "libcycript"
        ]
        
        for libraryIndex in 0..<_dyld_image_count() {
            
            // _dyld_get_image_name returns const char * that needs to be casted to Swift String
            guard let loadedLibrary = String(validatingUTF8: _dyld_get_image_name(libraryIndex)) else { continue }
            
            for suspiciousLibrary in suspiciousLibraries {
                if loadedLibrary.contains(suspiciousLibrary) {
                    return true
                }
            }
        }
        
        return false
    }
    
    private static func checkExistenceOfSuspiciousFiles() -> Bool {
        
        let paths = [
            "/usr/sbin/frida-server"
        ]
        
        // NOTE: you could e.g. wrap this into one-liner
        // return paths.first { FileManager.default.fileExists(atPath: $0) } != nil
        // for me it would be more readable as it could be read : "Return first path to satisfy the condition, if such path exists something is suspicious :)
        //
        // You could probably think of a solution to check all the paths and provide a user some readable feedback what paths have been actually detected - but I assume this could be in the next framework release.
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkOpenPorts() -> Bool {
        
        func swapBytesIfNeeded(port: in_port_t) -> in_port_t {
            let littleEndian = Int(OSHostByteOrder()) == OSLittleEndian
            return littleEndian ? _OSSwapInt16(port) : port
        }
        
        let ports = [
            27042, // default Frida
            4444 // default Needle
        ]
        
        for port in ports {
            
            // NOTE: you could wrap this into some private method as it's a part which is not quickly readable (a part which touches some low level APIs)
            var serverAddress = sockaddr_in()
            serverAddress.sin_family = sa_family_t(AF_INET)
            serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1")
            serverAddress.sin_port = swapBytesIfNeeded(port: in_port_t(port))
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            
            let result = withUnsafePointer(to: &serverAddress) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
                }
            }
            
            // NOTE: I see some repetitions here everywhere in the code
            // Basically you take a Collection (Array) and check if at least one of the elements satisfy some condition.
            // You could possibly write some extension on `Collection` protocol with a method named e.g. `atLeastOneSatisfy`, you could actually get inspired by `allSatisfy` method which is in the Swift's stdlib
            if result != -1 {
                return true // Port is opened
            }
        }
        
        return false
    }
    
}
