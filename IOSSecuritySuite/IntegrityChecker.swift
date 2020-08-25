//
//  IntegrityChecker.swift
//  IOSSecuritySuite
//
//  Created by NikoXu on 2020/8/21.
//  Copyright © 2020 wregula. All rights reserved.
//

import Foundation
import MachO
import CommonCrypto


internal class IntegrityChecker {
    /// Check if the Mach-O file has been tampered with
    static func amITampered(_ expectedBundleID: String) -> Bool {
        if expectedBundleID != Bundle.main.bundleIdentifier {
            return true
        }
        
        return false
    }
    
}

#if arch(arm64)

public enum IntegrityCheckerImageTarget {
    /// Default image
    case `default`
    /// Custom image with a specified name
    case custom(String)
}

extension IntegrityChecker {
    
    /// Get hash value of Mach-O "__TXET.__text" data with a specified image target
    static func getExecutableFileHashValue(_ target: IntegrityCheckerImageTarget = .default) -> String? {
        switch target {
        case .custom(let imageName):
            return MachOParse(imageName: imageName).getTextSectionDataSHA256Value()
        case .default:
            return MachOParse().getTextSectionDataSHA256Value()
        }
    }
    
    /// Find loaded dylib with a specified image target
    static func findLoadedDylib(_ target: IntegrityCheckerImageTarget = .default) -> Array<String>? {
        switch target {
        case .custom(let imageName):
            return MachOParse(imageName: imageName).findLoadedDylib()
        case .default:
            return MachOParse().findLoadedDylib()
        }
    }
}

// MARK: - MachOParse

struct SectionInfo {
    var section: UnsafePointer<section_64>
    var addr: UInt64
}

struct SegmentInfo {
    var segment: UnsafePointer<segment_command_64>
    var addr: UInt64
}

/// Convert (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) to String
@inline(__always)
fileprivate func Convert16BitInt8TupleToString(int8Tuple: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8)) -> String {
    let mirror = Mirror(reflecting: int8Tuple)
    
    return mirror.children.map {
        String(UnicodeScalar(UInt8($0.value as! Int8)))
        }.joined().replacingOccurrences(of: "\0", with: "")
}

fileprivate class MachOParse {
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
    
    func findLoadedDylib() -> Array<String>? {
        guard let header = base else {
            return nil
        }
        
        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: header) + UInt(MemoryLayout<mach_header_64>.size)) else {
            return nil
        }
        
        var array: Array<String> = Array()
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
                let segName = Convert16BitInt8TupleToString(int8Tuple: segCmd.pointee.segname)
                
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
                let segName = Convert16BitInt8TupleToString(int8Tuple: segCmd.pointee.segname)
                
                if segname == segName {
                    for i in 0..<segCmd.pointee.nsects {
                        guard let sect = UnsafeMutablePointer<section_64>(bitPattern: UInt(bitPattern: curCmd) + UInt(MemoryLayout<segment_command_64>.size) + UInt(i)) else {
                            return nil
                        }
                        
                        let secName = Convert16BitInt8TupleToString(int8Tuple: sect.pointee.sectname)
                        
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
        
        // Hash: Sha256
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = CC_SHA256(startAddr, CC_LONG(size), &hash)
        
        return Data(hash).hexEncodedString()
    }
}

extension Data {
    fileprivate func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

extension String {
    
    /// Convert String to UnsafePointer<Int8>
    fileprivate func convertCString(usig encoding: String.Encoding = .utf8) -> UnsafePointer<Int8> {
        let data = self.data(using: encoding)!
        let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        defer {
            bytes.deallocate()
        }
        data.copyBytes(to: bytes, count: data.count)
        return UnsafeRawPointer(bytes).assumingMemoryBound(to: CChar.self)
    }
}

extension UnsafeMutablePointer {
    
    ///  Compare C string
    fileprivate func equalUnsafePointer<T> (other:UnsafePointer<T>) ->Bool{
        let cStringValue = unsafeDowncast(self.pointee as AnyObject, to: CFString.self)
        let cOtherStringValue = unsafeDowncast(other.pointee as AnyObject, to: CFString.self)
        return cStringValue == cOtherStringValue
    }
    
    /// Convert UnsafeMutablePointer to Swift String
    fileprivate func toString() -> String   {
        let cBuffer =  UnsafeRawPointer(self).assumingMemoryBound(to: CChar.self)
        return String.init(cString: cBuffer)
    }
}

extension UnsafePointer {
    /// Convert UnsafePointer to Swift String
    fileprivate func  toValue() -> String {
        let unsafeMutablePointer =  UnsafeMutablePointer(mutating: self)
        let cBuffer = UnsafeMutableRawPointer(unsafeMutablePointer).assumingMemoryBound(to: CChar.self)
        return String(cString: cBuffer)
    }
}

#endif
