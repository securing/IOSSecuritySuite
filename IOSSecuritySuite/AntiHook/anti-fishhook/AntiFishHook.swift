//
//  FishHookProtection.swift
//  FishHookProtect
//
//  Created by jintao on 2019/3/25.
//  Copyright © 2019 jintao. All rights reserved.
//

import Foundation
import MachO

// __stub_helper
fileprivate let __stub_helper_section: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0x5f, 0x5f, 0x73, 0x74, 0x75, 0x62, 0x5f, 0x68, 0x65, 0x6c, 0x70, 0x65, 0x72, 0x00, 0x00, 0x00)

@inline(__always)
@_cdecl("resetSymbol")  // support Swift, OC
public func resetSymbol(_ symbol: String) {
    for i in 0..<_dyld_image_count() {
        if let image = _dyld_get_image_header(i) {
            resetSymbol(symbol, image: image, imageSlide: _dyld_get_image_vmaddr_slide(i))
        }
    }
}

@inline(__always)
public func resetSymbol(_ symbol: String,
                         image: UnsafePointer<mach_header>,
                         imageSlide slide: Int) {
    // Linked cmd
    let linkeditCmdName = SEG_LINKEDIT.data(using: String.Encoding.utf8)!.map({ $0 })
    var linkeditCmd: UnsafeMutablePointer<segment_command_64>!
    var dyldInfoCmd: UnsafeMutablePointer<dyld_info_command>!
    
    // Text cmd
    let textCmdName = SEG_TEXT.data(using: String.Encoding.utf8)!.map({ Int8($0) })
    var textCmd: UnsafeMutablePointer<segment_command_64>!
    
    guard var cur_cmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: image)+UInt(MemoryLayout<mach_header_64>.size)) else { return }
    
    for _ in 0..<image.pointee.ncmds {
        cur_cmd = UnsafeMutableRawPointer(cur_cmd).advanced(by: Int(cur_cmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
        
        if cur_cmd.pointee.cmd == LC_SEGMENT_64 {
            if (cur_cmd.pointee.segname.0 == linkeditCmdName[0] &&
                cur_cmd.pointee.segname.1 == linkeditCmdName[1] &&
                cur_cmd.pointee.segname.2 == linkeditCmdName[2] &&
                cur_cmd.pointee.segname.3 == linkeditCmdName[3] &&
                cur_cmd.pointee.segname.4 == linkeditCmdName[4] &&
                cur_cmd.pointee.segname.5 == linkeditCmdName[5] &&
                cur_cmd.pointee.segname.6 == linkeditCmdName[6] &&
                cur_cmd.pointee.segname.7 == linkeditCmdName[7] &&
                cur_cmd.pointee.segname.8 == linkeditCmdName[8] &&
                cur_cmd.pointee.segname.9 == linkeditCmdName[9]) {
                
                linkeditCmd = cur_cmd
            }
            if (cur_cmd.pointee.segname.0 == textCmdName[0] &&
                cur_cmd.pointee.segname.1 == textCmdName[1] &&
                cur_cmd.pointee.segname.2 == textCmdName[2] &&
                cur_cmd.pointee.segname.3 == textCmdName[3] &&
                cur_cmd.pointee.segname.4 == textCmdName[4] &&
                cur_cmd.pointee.segname.5 == textCmdName[5]) {
                
                textCmd = cur_cmd
            }
        } else if cur_cmd.pointee.cmd == LC_DYLD_INFO_ONLY || cur_cmd.pointee.cmd == LC_DYLD_INFO {
            dyldInfoCmd = UnsafeMutablePointer<dyld_info_command>(OpaquePointer(UnsafeRawPointer(cur_cmd)))
        }
    }
    
    if linkeditCmd == nil || dyldInfoCmd == nil || textCmd == nil { return }
    
    let linkeditBase = UInt64(slide) + linkeditCmd.pointee.vmaddr - linkeditCmd.pointee.fileoff
    let lazyBindInfoCmd = linkeditBase + UInt64(dyldInfoCmd.pointee.lazy_bind_off)
//    let bindInfoCmd = linkeditBase + UInt64(dyldInfoCmd.pointee.bind_off)
    
    if !rebindLazySymbol(symbol: symbol, image: image, imageSlide: slide, text_cmd: textCmd, lazyBindInfoCmd: UnsafePointer<UInt8>(bitPattern: UInt(lazyBindInfoCmd)), lazyBindInfoSize: Int(dyldInfoCmd.pointee.lazy_bind_size)) {
        
        rebindNonLazySymbol2(symbol, image: image, imageSlide: slide)
    }
}

// if symbol is LazySymbol
// dyld_stub_binder => fastBindLazySymbol => doBindFastLazySymbol => ImageLoaderMachO::getLazyBindingInfo
@inline(__always)
private func rebindLazySymbol(symbol: String,
                               image: UnsafePointer<mach_header>,
                               imageSlide slide: Int,
                               text_cmd: UnsafeMutablePointer<segment_command_64>,
                               lazyBindInfoCmd: UnsafePointer<UInt8>!,
                               lazyBindInfoSize: Int) -> Bool {
    if lazyBindInfoCmd == nil { return false}
    var stub_helper_section: UnsafeMutablePointer<section_64>!
    
    for i in 0..<text_cmd.pointee.nsects {
        let cur_section_pointer = UnsafeRawPointer(text_cmd).advanced(by: MemoryLayout<segment_command_64>.size + MemoryLayout<section_64>.size*Int(i))
        let curSection = UnsafeMutablePointer<section_64>(OpaquePointer(cur_section_pointer))
        
        if curSection.pointee.sectname.0 == __stub_helper_section.0 &&
            curSection.pointee.sectname.1 == __stub_helper_section.1 &&
            curSection.pointee.sectname.2 == __stub_helper_section.2 &&
            curSection.pointee.sectname.3 == __stub_helper_section.3 &&
            curSection.pointee.sectname.4 == __stub_helper_section.4 &&
            curSection.pointee.sectname.5 == __stub_helper_section.5 &&
            curSection.pointee.sectname.6 == __stub_helper_section.6 &&
            curSection.pointee.sectname.7 == __stub_helper_section.7 &&
            curSection.pointee.sectname.8 == __stub_helper_section.8 &&
            curSection.pointee.sectname.9 == __stub_helper_section.9 &&
            curSection.pointee.sectname.10 == __stub_helper_section.10 &&
            curSection.pointee.sectname.11 == __stub_helper_section.11 &&
            curSection.pointee.sectname.12 == __stub_helper_section.12
        {
            stub_helper_section = curSection
            break
        }
    }
    
    // find code vm addr
    guard stub_helper_section != nil,
        let stubHelper_vm_addr = UnsafeMutablePointer<UInt32>(bitPattern: slide+Int(stub_helper_section.pointee.addr)) else {
            return false
        }
    
    var codeOffset: Int!
    // 5 instructions: code of dyld_stub_binder
    for i in 5..<stub_helper_section.pointee.size/4 {
        /*
            ldr w16 .long
            b: stub(dyld_stub_binder)
            .long: symbol_bindInfo_offset
         */
        
        /*   ldr w16, #8  ARM Architecture Reference Manual

             0x18000050 is feature at IDA, so decompile instruction
         
             31  28 27 25
             +-----------------------------------------------------------------------+
             |cond | 100 | P | U | S | W | L | Rn |         register list            |
             +-----------------------------------------------------------------------+
         
             If R15 is specified as register Rn, the value used is the address of the instruction plus eight.
         */
        let instruction = stubHelper_vm_addr.advanced(by: Int(i)).pointee
        let ldr = (instruction & (7 << 25)) >> 25
        let r16 = instruction & (31 << 0)
        
        // 100 && r16
        if ldr == 4 && r16 == 16 {
            let bindingInfoOffset = stubHelper_vm_addr.advanced(by: Int(i+2)).pointee
            var p = bindingInfoOffset
            
            Label: while p < lazyBindInfoSize  {
                if lazyBindInfoCmd.advanced(by: Int(p)).pointee == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB {
                    p += 3 // pass uleb128
                    continue Label
                }
                if lazyBindInfoCmd.advanced(by: Int(p)).pointee == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM {
                    // _symbol
                    if String(cString: lazyBindInfoCmd.advanced(by: Int(p)+1 + 1)) == symbol {
                        codeOffset = Int(i)
                        break
                    }
                    break Label
                }
                p += 1
                continue Label
            }
        }
        
    }
    
    if codeOffset == nil {
        return false
    }
    
    let pointer = stubHelper_vm_addr.advanced(by: (codeOffset))  // ldr w16 .long
    let newMethod = UnsafeMutablePointer(pointer)
    var oldMethod: UnsafeMutableRawPointer? = nil
    replaceSymbol(symbol, image: image, imageSlide: slide, newMethod: newMethod, oldMethod: &oldMethod)
    
    return true
}

/*  Not Release
 
// if symbol is non_lazy_symbol
// ImageLoader::recursiveBind => doBind => eachBind => bindAt => findByExportedSymbol
@inline(__always)
private func rebindNonLazySymbol(_ symbol: String,
                                    image: UnsafePointer<mach_header>,
                                    imageSlide slide: Int,
                                    bindInfoCmd: UnsafePointer<UInt8>!,
                                    bindInfoSize: Int) {
    
    let all_load_dyld = getAllLoadDyld(image: image)
    var libraryOrdinal: Int?
    
    // wait to do for opcode
    for i in 0..<bindInfoSize {
        let opcode = Int32(bindInfoCmd.pointee) & BIND_OPCODE_MASK
        let immediate = Int32(bindInfoCmd.pointee) & BIND_IMMEDIATE_MASK
        
Label: switch opcode {
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            libraryOrdinal = Int(immediate)
            
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            let symbolName = String(cString: bindInfoCmd.advanced(by: Int(i)+1))
            let _symbolName = String(cString: bindInfoCmd.advanced(by: Int(i)+1 + 1))
            
            if symbolName == symbol || _symbolName == symbol, libraryOrdinal != nil {
                break
            }
            libraryOrdinal = nil
        default:
            libraryOrdinal = nil
            break Label
        }
    }
    
    if libraryOrdinal != nil, libraryOrdinal! <= all_load_dyld.count {
        let dyldName = all_load_dyld[Int(libraryOrdinal!-1)]
        
        // 1.
        let handle = dlopen(dyldName, RTLD_NOW)
        // 2. Exported Symbol
        if let symPointer = dlsym(handle, symbol) {
            var oldMethod: UnsafeMutableRawPointer? = nil
            // 3. replace
            replaceSymbol(symbol, image: image, imageSlide: slide, newMethod: symPointer, oldMethod: &oldMethod)
        }
    }
}
 
*/

// if symbol is non_lazy_symbol
// ImageLoader::recursiveBind => doBind => eachBind => bindAt => findByExportedSymbol
@inline(__always)
private func rebindNonLazySymbol2(_ symbol: String,
                                    image: UnsafePointer<mach_header>,
                                    imageSlide slide: Int) {
    // 1. dlopen
    // 2. dlsym
    // 3. replace

    // 0. which dyld is the symbol at
    let all_load_dyld = getAllLoadDyld(image: image)
    
    // __Linkedit cmd
    var linkeditCmd: UnsafeMutablePointer<segment_command_64>!
    let linkeditName = SEG_LINKEDIT.data(using: String.Encoding.utf8)!.map({ $0 })
    
    // Symbol cmd
    var symtabCmd: UnsafeMutablePointer<symtab_command>!
    var dynamicSymtabCmd: UnsafeMutablePointer<dysymtab_command>!
    
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
        } else if cur_cmd.pointee.cmd == LC_SYMTAB {
            symtabCmd = UnsafeMutablePointer<symtab_command>(OpaquePointer(cur_cmd))
        }  else if cur_cmd.pointee.cmd == LC_DYSYMTAB {
            dynamicSymtabCmd = UnsafeMutablePointer<dysymtab_command>(OpaquePointer(cur_cmd))
        }
    }
    
    if linkeditCmd == nil || symtabCmd == nil || dynamicSymtabCmd == nil || all_load_dyld.count == 0 {
        return
    }
    
    let linkedBase = slide + Int(linkeditCmd.pointee.vmaddr) - Int(linkeditCmd.pointee.fileoff)
    let symtab = UnsafeMutablePointer<nlist_64>(bitPattern: linkedBase + Int(symtabCmd.pointee.symoff))
    let strtab =  UnsafeMutablePointer<UInt8>(bitPattern: linkedBase + Int(symtabCmd.pointee.stroff))
    let indirectsym = UnsafeMutablePointer<UInt32>(bitPattern: linkedBase + Int(dynamicSymtabCmd.pointee.indirectsymoff))
    
    if symtab == nil || strtab == nil || indirectsym == nil {
        return
    }
    
    var dyldName: String!
    
    for i in 0..<dynamicSymtabCmd.pointee.nindirectsyms {
        let offset = indirectsym!.advanced(by: Int(i)).pointee
        let _symbol = symtab!.advanced(by: Int(offset))
        
        let strOff = _symbol.pointee.n_un.n_strx
        let symbolName = strtab!.advanced(by: Int(strOff))
        let _symbolName = strtab!.advanced(by: Int(strOff+1))
    
        if String(cString: symbolName) == symbol || String(cString: _symbolName) == symbol {
            if let load_dyld_offset = get_library_ordinal(_symbol.pointee.n_desc),
                load_dyld_offset <= all_load_dyld.count {
                dyldName = all_load_dyld[Int(load_dyld_offset-1)]
            }
            break
        }
    }
    
    if dyldName == nil { return }
    
    // 1.
    let handle = dlopen(dyldName, RTLD_NOW)
    
    // 2. Exported Symbol
    if let symPointer = dlsym(handle, symbol) {
        var oldMethod: UnsafeMutableRawPointer? = nil
        // 3. replace
        replaceSymbol(symbol, image: image, imageSlide: slide, newMethod: symPointer, oldMethod: &oldMethod)
    }
}

// https://developer.apple.com/documentation/kernel/nlist_64/1583957-n_desc?language=objc
private func get_library_ordinal(_ value: UInt16) -> Int? {
//  REFERENCE_FLAG_UNDEFINED_NON_LAZY = 0x0
    if value & 0x00ff == 0x0 {
        return Int((value >> 8) & 0xff)
    }
    return nil
}

private func getAllLoadDyld(image: UnsafePointer<mach_header>) -> [String] {
    var all_load_dyld = [String]()
    
    guard var cur_cmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: image)+UInt(MemoryLayout<mach_header_64>.size)) else { return all_load_dyld }
       
    for _ in 0..<image.pointee.ncmds {
        cur_cmd = UnsafeMutableRawPointer(cur_cmd).advanced(by: Int(cur_cmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
        
        if cur_cmd.pointee.cmd == LC_LOAD_DYLIB ||
            cur_cmd.pointee.cmd == LC_LOAD_WEAK_DYLIB ||
            cur_cmd.pointee.cmd == LC_REEXPORT_DYLIB {
        
            if let dyld_cmd = UnsafeMutablePointer<dylib_command>(bitPattern: UInt(bitPattern: cur_cmd)) {
                let str_off = dyld_cmd.pointee.dylib.name.offset
                let dyld_c_name = UnsafeMutableRawPointer(dyld_cmd).advanced(by: Int(str_off)).assumingMemoryBound(to: UInt8.self)
                all_load_dyld.append(String(cString: dyld_c_name))
            }
        }
    }
    
    return all_load_dyld
}
