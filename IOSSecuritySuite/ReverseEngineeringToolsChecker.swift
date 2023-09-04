//
//  ReverseEngineeringToolsChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 24/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
// swiftlint:disable trailing_whitespace

import Foundation
import MachO // dyld

internal class ReverseEngineeringToolsChecker {
    typealias CheckResult = (passed: Bool, failMessage: String)

    struct ReverseEngineeringToolsStatus {
        let passed: Bool
        let failedChecks: [FailedCheckType]
    }

    static func amIReverseEngineered() -> Bool {
        return !performChecks().passed
    }

    @inline(__always) static func amIReverseEngineeredWithFailedChecks() -> (reverseEngineered: Bool, failedChecks: [FailedCheckType]) {
        let status = performChecks()
        return (!status.passed, status.failedChecks)
    }
  
    @inline(__always) private static func performChecks() -> ReverseEngineeringToolsStatus {
        var passed = true
        var result: CheckResult = (true, "")
        var failedChecks: [FailedCheckType] = []
        
        for check in FailedCheck.allCases {
            switch check {
            case .existenceOfSuspiciousFiles:
                result = checkExistenceOfSuspiciousFiles()
            case .dyld:
                result = checkDYLD()
            case .openedPorts:
                result = checkOpenedPorts()
            case .pSelectFlag:
                result = checkPSelectFlag()
            default:
              continue
            }

            passed = passed && result.passed

            if !result.passed {
                failedChecks.append((check: check, failMessage: result.failMessage))
            }
        }

        return ReverseEngineeringToolsStatus(passed: passed, failedChecks: failedChecks)
    }

    private static func checkDYLD() -> CheckResult {

        let suspiciousLibraries: [[UInt8]] = [
            [15, 61, 58, 55, 4, 36, 20, 22, 14, 17, 13], // FridaGadget
            [47, 61, 58, 55, 4], // frida (Needle injects frida-somerandom.dylib)
            [42, 54, 61, 57, 0, 0, 1], // cynject
            [37, 38, 49, 48, 28, 0, 7, 27, 25, 0] // libcycript
        ]

        for libraryIndex in 0..<_dyld_image_count() {

            // _dyld_get_image_name returns const char * that needs to be casted to Swift String
            guard let loadedLibrary = String(validatingUTF8: _dyld_get_image_name(libraryIndex)) else { continue }

            for suspiciousLibrary in suspiciousLibraries {
                if loadedLibrary.lowercased().contains(Obfuscator().reveal(key: suspiciousLibrary).lowercased()) {
                    return (false, "Suspicious library loaded: \(loadedLibrary)")
                }
            }
        }

        return (true, "")
    }

    private static func checkExistenceOfSuspiciousFiles() -> CheckResult {

        let paths: [[UInt8]] = [
            [102, 58, 32, 33, 74, 16, 23, 27, 7, 91, 31, 33, 28, 13, 21, 72, 57, 4, 27, 26, 7, 0] // /usr/sbin/frida-server
        ]

        for path in paths {
            if FileManager.default.fileExists(atPath: Obfuscator().reveal(key: path)) {
                return (false, "Suspicious file found: \(path)")
            }
        }

        return (true, "")
    }

    private static func checkOpenedPorts() -> CheckResult {

        let ports: [[UInt8]] = [
            [123, 120, 99, 103, 87], // default Frida
            [125, 123, 103, 103] // default Needle
        ]
        
        for port in ports {

            if canOpenLocalConnection(port: Int(Obfuscator().reveal(key: port)) ?? 0) {
                return (false, "Port \(port) is open")
            }
        }

        return (true, "")
    }

    private static func canOpenLocalConnection(port: Int) -> Bool {

        func swapBytesIfNeeded(port: in_port_t) -> in_port_t {
            let littleEndian = Int(OSHostByteOrder()) == OSLittleEndian
            return littleEndian ? _OSSwapInt16(port) : port
        }

        var serverAddress = sockaddr_in()
        serverAddress.sin_family = sa_family_t(AF_INET)
        let fUHx2x: [UInt8] = [120, 125, 100, 125, 85, 77, 69, 92, 88] // 127.0.0.1
        serverAddress.sin_addr.s_addr = inet_addr(Obfuscator().reveal(key: fUHx2x))
        serverAddress.sin_port = swapBytesIfNeeded(port: in_port_t(port))
        let sock = socket(AF_INET, SOCK_STREAM, 0)

        let result = withUnsafePointer(to: &serverAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }
        
        defer {
            close(sock)
        }

        if result != -1 {
            return true // Port is opened
        }

        return false
    }
    
    // EXPERIMENTAL
    private static func checkPSelectFlag() -> CheckResult {
        var kinfo = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let sysctlRet = sysctl(&mib, UInt32(mib.count), &kinfo, &size, nil, 0)

        if sysctlRet != 0 {
            print("Error occured when calling sysctl(). This check may not be reliable")
        }
        
        if (kinfo.kp_proc.p_flag & P_SELECT) != 0 {
            return (false, "Suspicious PFlag value")
        }
      
        return (true, "")
    }
}
