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

    static func amIReverseEngineeredWithFailedChecks() -> (reverseEngineered: Bool, failedChecks: [FailedCheckType]) {
        let status = performChecks()
        return (!status.passed, status.failedChecks)
    }
  
    private static func performChecks() -> ReverseEngineeringToolsStatus {
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
                if loadedLibrary.lowercased().contains(suspiciousLibrary.lowercased()) {
                    return (false, "Suspicious library loaded: \(loadedLibrary)")
                }
            }
        }

        return (true, "")
    }

    private static func checkExistenceOfSuspiciousFiles() -> CheckResult {

        let paths = [
            "/usr/sbin/frida-server"
        ]

        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return (false, "Suspicious file found: \(path)")
            }
        }

        return (true, "")
    }

    private static func checkOpenedPorts() -> CheckResult {

        let ports = [
            27042, // default Frida
            4444, // default Needle
            22, // OpenSSH
            44 // checkra1n
        ]

        for port in ports {

            if canOpenLocalConnection(port: port) {
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
        serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1")
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
