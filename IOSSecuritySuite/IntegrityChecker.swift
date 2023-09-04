//
//  IntegrityChecker.swift
//  IOSSecuritySuite
//
//  Created by NikoXu on 2020/8/21.
//  Copyright © 2020 wregula. All rights reserved.
//
// swiftlint:disable line_length large_tuple force_cast trailing_whitespace

import Foundation
import MachO
import CommonCrypto

protocol Explainable {
    var description: String { get }
}

public enum FileIntegrityCheck {
    // Compare current bundleID with a specified bundleID.
    case bundleID(String)
    
    // Compare current hash value(SHA256 hex string) of `embedded.mobileprovision` with a specified hash value.
    // Use command `"shasum -a 256 /path/to/embedded.mobileprovision"` to get SHA256 value on your macOS.
    case mobileProvision(String)
    
    // Compare current hash value(SHA256 hex string) of executable file with a specified (Image Name, Hash Value).
    // Only work on dynamic library and arm64.
    case machO(String, String)
    
    // Сhecks a special key in Bundle.infoDictionary that is usually added when the bundle was re-signed
    case bundleResigned

    // Checks that the application bundle contains a signature
    case signature

    // Checks that plist was not modified
    case plistModification

    // Checks that the application bundle encrypted
    case encryption
}

extension FileIntegrityCheck: Explainable {
    public var description: String {
        switch self {
        case .bundleID(let exceptedBundleID):
            return "Bundle ID mismatch"
        case .mobileProvision(let expectedSha256Value):
            return "The expected hash value of Mobile Provision file was \(expectedSha256Value)"
        case .machO(let imageName, let expectedSha256Value):
            return "The expected hash value of \"__TEXT.__text\" data of \(imageName) Mach-O file was \(expectedSha256Value)"
        case .bundleResigned:
            return "App was re-signed"
        case .signature:
            return "Signature not exists"
        case .plistModification:
            return "Info.plist was modified"
        case .encryption:
            return "App bundle not encrypted"
        }
    }
}

public typealias FileIntegrityCheckResult = (result: Bool, hitChecks: [FileIntegrityCheck])

internal class IntegrityChecker {
    
    // Check if the application has been tampered with the specified checks
    @inline(__always) static func amITampered(_ checks: [FileIntegrityCheck]) -> FileIntegrityCheckResult {
        
        var hitChecks: [FileIntegrityCheck] = []
        var result = false
        
        for check in checks {
            switch check {
            case .bundleID(let exceptedBundleID):
                if checkBundleID(exceptedBundleID) {
                    result = true
                    hitChecks.append(check)
                }
            case .mobileProvision(let expectedSha256Value):
                if checkMobileProvision(expectedSha256Value.lowercased()) {
                    result = true
                    hitChecks.append(check)
                }
            case .machO(let imageName, let expectedSha256Value):
                if checkMachO(imageName, with: expectedSha256Value.lowercased()) {
                    result = true
                    hitChecks.append(check)
                }
            case .bundleResigned:
                if checkIsBundleResigned() {
                    result = true
                    hitChecks.append(check)
                }
            case .signature:
                if !checkSignatureExistence() {
                    result = true
                    hitChecks.append(check)
                }
            case .plistModification:
                if checkIsPlistModified() {
                    result = true
                    hitChecks.append(check)
                }
            case .encryption:
                if !checkIsBundleEncrypted() {
                    result = true
                    hitChecks.append(check)
                }
            }
        }
        
        return (result, hitChecks)
    }
    
    private static func checkBundleID(_ expectedBundleID: String) -> Bool {
        if expectedBundleID != Bundle.main.bundleIdentifier {
            return true
        }
        
        return false
    }
    
    private static func checkMobileProvision(_ expectedSha256Value: String) -> Bool {
        
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else { return false }

        let url = URL(fileURLWithPath: path)
        
        if FileManager.default.fileExists(atPath: url.path) {
            if let data = FileManager.default.contents(atPath: url.path) {
                
                // Hash: SHA256
                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                data.withUnsafeBytes {
                    _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
                }
                
                if Data(hash).hexEncodedString() != expectedSha256Value {
                    return true
                }
            }
        }
        
        return false
    }
    
    private static func checkMachO(_ imageName: String, with expectedSha256Value: String) -> Bool {
#if arch(arm64)
        if let hashValue = getMachOFileHashValue(.custom(imageName)), hashValue != expectedSha256Value {
            return true
        }
#endif
        return false
    }
    
    
    // This key can be only in a hacked app
    // https://github.com/olxios/SmartSec_iOS_Security/blob/master/SmartSec/SmartSec/checks/integrity/IntegrityCheck1.m
    private static func checkIsBundleResigned() -> Bool {
        // SignerIdentity
        let key: [UInt8] = [26, 38, 52, 61, 0, 17, 60, 22, 12, 26, 13, 58, 1, 16]
        return Bundle.main.infoDictionary?[Obfuscator().reveal(key: key)] != nil
    }

    // Check that signature exists
    // https://github.com/olxios/SmartSec_iOS_Security/blob/master/SmartSec/SmartSec/checks/integrity/IntegrityCheck1.m
    private static func checkSignatureExistence() -> Bool {
        let bundlePath = NSString(string: Bundle.main.bundlePath)
        // _CodeSignature
        let pathComponent: [UInt8] = [22, 12, 60, 55, 0, 48, 28, 21, 7, 21, 13, 38, 7, 12]
        let signaturePath = bundlePath.appendingPathComponent(Obfuscator().reveal(key: pathComponent))
        return FileManager.default.fileExists(atPath: signaturePath)
    }

    // Check that plist modified
    // https://github.com/olxios/SmartSec_iOS_Security/blob/master/SmartSec/SmartSec/checks/integrity/IntegrityCheck1.m
    private static func checkIsPlistModified() -> Bool {
        let bundle = Bundle.main
        let bundlePath = NSString(string: Bundle.main.bundlePath)
        // Info.plist
        let pathComponent: [UInt8] = [0, 33, 53, 60, 75, 19, 25, 27, 26, 0]

        let plistPath = bundlePath.appendingPathComponent(Obfuscator().reveal(key: pathComponent))
        let plistAttributes = try? FileManager.default.attributesOfItem(atPath: plistPath)

        guard let executablePath = bundle.executablePath else {
            return true
        }
        let executableFileAttributes = try? FileManager.default.attributesOfItem(atPath: executablePath)

        if let plistModificationDate = plistAttributes?[.modificationDate] as? Date,
           let executableModificationDate = executableFileAttributes?[.modificationDate] as? Date,
           plistModificationDate.timeIntervalSince1970 > executableModificationDate.timeIntervalSince1970 {
            return true
        }

        return false
    }

    // Check is bundle encrypted
    // https://github.com/olxios/SmartSec_iOS_Security/blob/master/SmartSec/SmartSec/checks/integrity/IntegrityCheck2.m
    private static func checkIsBundleEncrypted() -> Bool {
        guard let header = _dyld_get_image_header(0) else {
            return false
        }

        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: header)+UInt(MemoryLayout<mach_header_64>.size)) else {
            return false
        }

        var segCmd: UnsafeMutablePointer<segment_command_64>!

        for _ in 0..<header.pointee.ncmds {
            segCmd = curCmd
            if segCmd.pointee.cmd == LC_ENCRYPTION_INFO_64 {
                let cryptCmd = UnsafeMutableRawPointer(segCmd).assumingMemoryBound(to: encryption_info_command_64.self)

                return cryptCmd.pointee.cryptid > 0
            }

            curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
        }

        return false
    }
}

#if arch(arm64)

public enum IntegrityCheckerImageTarget {
    // Default image
    case `default`
    
    // Custom image with a specified name
    case custom(String)
}

extension IntegrityChecker {
    
    // Get hash value of Mach-O "__TEXT.__text" data with a specified image target
    static func getMachOFileHashValue(_ target: IntegrityCheckerImageTarget = .default) -> String? {
        switch target {
        case .custom(let imageName):
            return MachOParse(imageName: imageName).getTextSectionDataSHA256Value()
        case .default:
            return MachOParse().getTextSectionDataSHA256Value()
        }
    }
    
    // Find loaded dylib with a specified image target
    static func findLoadedDylibs(_ target: IntegrityCheckerImageTarget = .default) -> [String]? {
        switch target {
        case .custom(let imageName):
            return MachOParse(imageName: imageName).findLoadedDylibs()
        case .default:
            return MachOParse().findLoadedDylibs()
        }
    }
}

// MARK: - MachOParse

private struct SectionInfo {
    var section: UnsafePointer<section_64>
    var addr: UInt64
}

private struct SegmentInfo {
    var segment: UnsafePointer<segment_command_64>
    var addr: UInt64
}

// Convert (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) to String
@inline(__always)
private func convert16BitInt8TupleToString(int8Tuple: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8)) -> String {
    let mirror = Mirror(reflecting: int8Tuple)
    
    return mirror.children.map {
        String(UnicodeScalar(UInt8($0.value as! Int8)))
        }.joined().replacingOccurrences(of: "\0", with: "")
}

private class MachOParse {
    private var base: UnsafePointer<mach_header>?
    private var slide: Int?
    
    init() {
        base    = _dyld_get_image_header(0)
        slide   = _dyld_get_image_vmaddr_slide(0)
    }
    
    init(header: UnsafePointer<mach_header>, slide: Int) {
        self.base   = header
        self.slide  = slide
    }
    
    init(imageName: String) {
        for index in 0..<_dyld_image_count() {
            if let cImgName = _dyld_get_image_name(index), String(cString: cImgName).contains(imageName),
                let header  = _dyld_get_image_header(index) {
                self.base   = header
                self.slide  = _dyld_get_image_vmaddr_slide(index)
            }
        }
    }
    
    private func vm2real(_ vmaddr: UInt64) -> UInt64? {
        guard let slide = slide else {
            return nil
        }
        
        return UInt64(slide) + vmaddr
    }
    
    func findLoadedDylibs() -> [String]? {
        guard let header = base else {
            return nil
        }
        
        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: header) + UInt(MemoryLayout<mach_header_64>.size)) else {
            return nil
        }
        
        var array: [String] = Array()
        var segCmd: UnsafeMutablePointer<segment_command_64>!
        
        for _ in 0..<header.pointee.ncmds {
            segCmd = curCmd
            if segCmd.pointee.cmd == LC_LOAD_DYLIB || segCmd.pointee.cmd == LC_LOAD_WEAK_DYLIB {
                if let dylib = UnsafeMutableRawPointer(segCmd)?.assumingMemoryBound(to: dylib_command.self),
                    let cName = UnsafeMutableRawPointer(dylib)?.advanced(by: Int(dylib.pointee.dylib.name.offset)).assumingMemoryBound(to: CChar.self) {
                    let dylibName = String(cString: cName)
                    array.append(dylibName)
                }
            }
            
            curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
        }
        
        return array
    }
    
    func findSegment(_ segname: String) -> SegmentInfo? {
        guard let header = base else {
            return nil
        }
        
        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: header)+UInt(MemoryLayout<mach_header_64>.size)) else {
            return nil
        }
        
        var segCmd: UnsafeMutablePointer<segment_command_64>!
        
        for _ in 0..<header.pointee.ncmds {
            segCmd = curCmd
            if segCmd.pointee.cmd == LC_SEGMENT_64 {
                let segName = convert16BitInt8TupleToString(int8Tuple: segCmd.pointee.segname)
                
                if segname == segName,
                    let vmaddr = vm2real(segCmd.pointee.vmaddr) {
                    let segmentInfo = SegmentInfo(segment: segCmd, addr: vmaddr)
                    return segmentInfo
                }
            }
            
            curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
        }
        
        return nil
    }
    
    func findSection(_ segname: String, secname: String) -> SectionInfo? {
        guard let header = base else {
            return nil
        }
        
        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: header)+UInt(MemoryLayout<mach_header_64>.size)) else {
            return nil
        }
        
        var segCmd: UnsafeMutablePointer<segment_command_64>!
        
        for _ in 0..<header.pointee.ncmds {
            segCmd = curCmd
            if segCmd.pointee.cmd == LC_SEGMENT_64 {
                let segName = convert16BitInt8TupleToString(int8Tuple: segCmd.pointee.segname)
                
                if segname == segName {
                    for sectionID in 0..<segCmd.pointee.nsects {
                        guard let sect = UnsafeMutablePointer<section_64>(bitPattern: UInt(bitPattern: curCmd) + UInt(MemoryLayout<segment_command_64>.size) + UInt(sectionID)) else {
                            return nil
                        }
                        
                        let secName = convert16BitInt8TupleToString(int8Tuple: sect.pointee.sectname)
                        
                        if secName == secname,
                            let addr = vm2real(sect.pointee.addr) {
                            let sectionInfo = SectionInfo(section: sect, addr: addr)
                            return sectionInfo
                        }
                    }
                }
            }
            
            curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
        }
        
        return nil
    }
    
    func getTextSectionDataSHA256Value() -> String? {
        guard let sectionInfo = findSection(SEG_TEXT, secname: SECT_TEXT) else {
            return nil
        }
        
        guard let startAddr = UnsafeMutablePointer<Any>(bitPattern: Int(sectionInfo.addr)) else {
            return nil
        }
        
        let size = sectionInfo.section.pointee.size
        
        // Hash: SHA256
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = CC_SHA256(startAddr, CC_LONG(size), &hash)
        
        return Data(hash).hexEncodedString()
    }
}

#endif

extension Data {
    fileprivate func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
