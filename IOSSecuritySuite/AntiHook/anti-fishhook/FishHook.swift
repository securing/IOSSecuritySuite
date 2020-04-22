//
//  FishHook.swift
//  FishHookProtect
//
//  Created by jintao on 2019/3/28.
//  Copyright © 2019 jintao. All rights reserved.
//

import Foundation
import MachO

@inline(__always)  // just for Swift
public func replaceSymbol(_ symbol: String,
                          newMethod: UnsafeMutableRawPointer,
                          oldMethod: inout UnsafeMutableRawPointer?)
{
    for i in 0..<_dyld_image_count() {
        if let image = _dyld_get_image_header(i) {
            replaceSymbol(symbol, image: image, imageSlide: _dyld_get_image_vmaddr_slide(i), newMethod: newMethod, oldMethod: &oldMethod)
        }
    }
}

@inline(__always)
public func replaceSymbol(_ symbol: String,
                          image: UnsafePointer<mach_header>,
                          imageSlide slide: Int,
                          newMethod: UnsafeMutableRawPointer,
                          oldMethod: inout UnsafeMutableRawPointer?)
{
    replaceSymbolAtImage(image, imageSlide: slide, symbol: symbol, newMethod: newMethod, oldMethod: &oldMethod)
}

@inline(__always)
private func replaceSymbolAtImage(_ image: UnsafePointer<mach_header>,
                                 imageSlide slide: Int,
                                 symbol: String,
                                 newMethod: UnsafeMutableRawPointer,
                                 oldMethod: inout UnsafeMutableRawPointer?)
{
    // __Linkedit cmd
    var linkeditCmd: UnsafeMutablePointer<segment_command_64>!
    let linkeditName = SEG_LINKEDIT.data(using: String.Encoding.utf8)!.map({ $0 })
    
    // Symbol cmd
    var symtabCmd: UnsafeMutablePointer<symtab_command>!
    var dynamicSymtabCmd: UnsafeMutablePointer<dysymtab_command>!
    
    // __Data cmd
    var dataCmd: UnsafeMutablePointer<segment_command_64>!
    let seg_data = SEG_DATA.data(using: String.Encoding.utf8)!.map({ Int8($0) })
    
    
    guard var cur_cmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: image)+UInt(MemoryLayout<mach_header_64>.size)) else { return }
    
    for _ in 0..<image.pointee.ncmds {
        cur_cmd = UnsafeMutableRawPointer(cur_cmd).advanced(by: Int(cur_cmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
        
        if cur_cmd.pointee.cmd == LC_SEGMENT_64 {
            if UInt8(cur_cmd.pointee.segname.0) == linkeditName[0] &&
                UInt8(cur_cmd.pointee.segname.1) == linkeditName[1] &&
                UInt8(cur_cmd.pointee.segname.2) == linkeditName[2] &&
                UInt8(cur_cmd.pointee.segname.3) == linkeditName[3] &&
                UInt8(cur_cmd.pointee.segname.4) == linkeditName[4] &&
                UInt8(cur_cmd.pointee.segname.5) == linkeditName[5] &&
                UInt8(cur_cmd.pointee.segname.6) == linkeditName[6] &&
                UInt8(cur_cmd.pointee.segname.7) == linkeditName[7] &&
                UInt8(cur_cmd.pointee.segname.8) == linkeditName[8] &&
                UInt8(cur_cmd.pointee.segname.9) == linkeditName[9] {
                
                linkeditCmd = cur_cmd
            }
            if cur_cmd.pointee.segname.0 == seg_data[0] &&
                cur_cmd.pointee.segname.1 == seg_data[1] &&
                cur_cmd.pointee.segname.2 == seg_data[2] &&
                cur_cmd.pointee.segname.3 == seg_data[3] &&
                cur_cmd.pointee.segname.4 == seg_data[4] &&
                cur_cmd.pointee.segname.5 == seg_data[5] {
                
                dataCmd = cur_cmd
            }
            
        } else if cur_cmd.pointee.cmd == LC_SYMTAB {
            symtabCmd = UnsafeMutablePointer<symtab_command>(OpaquePointer(cur_cmd))
        }  else if cur_cmd.pointee.cmd == LC_DYSYMTAB {
            dynamicSymtabCmd = UnsafeMutablePointer<dysymtab_command>(OpaquePointer(cur_cmd))
        }
    }
    
    if linkeditCmd == nil || symtabCmd == nil || dynamicSymtabCmd == nil || dataCmd == nil {
        return
    }
    
    let linkedBase = slide + Int(linkeditCmd.pointee.vmaddr) - Int(linkeditCmd.pointee.fileoff)
    let symtab = UnsafeMutablePointer<nlist_64>(bitPattern: linkedBase + Int(symtabCmd.pointee.symoff))
    let strtab =  UnsafeMutablePointer<UInt8>(bitPattern: linkedBase + Int(symtabCmd.pointee.stroff))
    let indirectsym = UnsafeMutablePointer<UInt32>(bitPattern: linkedBase + Int(dynamicSymtabCmd.pointee.indirectsymoff))
    
    if symtab == nil || strtab == nil || indirectsym == nil {
        return
    }
    
    for j in 0..<dataCmd.pointee.nsects {
        let cur_section = UnsafeMutableRawPointer(dataCmd).advanced(by: MemoryLayout<segment_command_64>.size + MemoryLayout<section_64>.size*Int(j)).assumingMemoryBound(to: section_64.self)
        
        // symbol_pointers sections
        if cur_section.pointee.flags == S_LAZY_SYMBOL_POINTERS {
            replaceSymbolPointerAtSection(cur_section, symtab: symtab!, strtab: strtab!, indirectsym: indirectsym!, slide: slide, symbolName: symbol, newMethod: newMethod, oldMethod: &oldMethod)
        }
        if cur_section.pointee.flags == S_NON_LAZY_SYMBOL_POINTERS {
            replaceSymbolPointerAtSection(cur_section, symtab: symtab!, strtab: strtab!, indirectsym: indirectsym!, slide: slide, symbolName: symbol, newMethod: newMethod, oldMethod: &oldMethod)
        }
    }
}

@inline(__always)
private func replaceSymbolPointerAtSection(_ section: UnsafeMutablePointer<section_64>,
                                           symtab: UnsafeMutablePointer<nlist_64>,
                                           strtab: UnsafeMutablePointer<UInt8>,
                                           indirectsym: UnsafeMutablePointer<UInt32>,
                                           slide: Int,
                                           symbolName: String,
                                           newMethod: UnsafeMutableRawPointer,
                                           oldMethod: inout UnsafeMutableRawPointer?)
{
    let indirectSym_vm_addr = indirectsym.advanced(by: Int(section.pointee.reserved1))
    let section_vm_addr = UnsafeMutablePointer<UnsafeMutableRawPointer>(bitPattern: slide+Int(section.pointee.addr))
    
    if section_vm_addr == nil {
        return
    }
    
Label: for i in 0..<Int(section.pointee.size)/MemoryLayout<UnsafeMutableRawPointer>.size {
        let curIndirectSym = indirectSym_vm_addr.advanced(by: i)
        if (curIndirectSym.pointee == INDIRECT_SYMBOL_ABS || curIndirectSym.pointee == INDIRECT_SYMBOL_LOCAL) {
            continue
        }
        let curStrTabOff = symtab.advanced(by: Int(curIndirectSym.pointee)).pointee.n_un.n_strx
        let curSymbolName = strtab.advanced(by: Int(curStrTabOff+1))
    
        if String(cString: curSymbolName) == symbolName {
            oldMethod = section_vm_addr!.advanced(by: i).pointee
            section_vm_addr!.advanced(by: i).initialize(to: newMethod)
            break
        }
    }
}
