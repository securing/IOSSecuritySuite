//
//  FishHookChecker.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/24.
//  Copyright © 2020 wregula. All rights reserved.
//  https://github.com/TannerJin/anti-fishhook

import Foundation
import MachO

/*
Lazy_Symbol_Ptr:
 
    call symbol2
    |
    |
    |   stubs(TEXT)
    |   *--------------*            stub_symbol:
    |   | stub_symbol1 |                         ldr x16 ptr   (ptr = pointer of lazy_symbol_ptr)
    |   |              |                         br x16
    *---> stub_symbol2 |
        |   ...        |
        *--------------*
 
 
    lazy_symbol_ptr(DATA)                   stub_helper(TEXT)
    *--------------*                        *---------------------------*
    |     ptr1     |                        |    br dyld_stub_binder    |    <-------------------*
    |     ptr2  ---------*                  |    symbol_binder_code_1   |                        |
    |     ptr3     |     *------------------->   symbol_binder_code_2   |                        |
    |     ...      |                        |          ...              |                        |
    *--------------*                        *---------------------------*                        |
                                                                                                 |
                                                   symbol_binder_code:                           |
                                                                       ldr w16, #8(.byte)        |
                                                                       b br_dyld_stub_binder  ---*
                                                                       .byte
 
 
    .byte of the symbol is offset which is from begin of lazy_binding_info to begin of symbol_info
 
    lazy_binding_info(LINKEDIT -> DYLD_INFO -> LazyBindingInfo)
    *-----------------*
    |  symbol_info_1  |          symbol_info:
    |  symbol_info_2  |                         bind_opcode_done
    |  symbol_info_3  |                         bind_opcode_set_segment_and_offset_uleb
    |  ...            |                         uleb128
    *-----------------*                         BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
                                                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
                                            **SymbolName**
                                                bind_opcode_do_bind
    
 
 
    The `denyFishHook` is look for code of `symbol_binder_code` of the symbol, and then make `lazy_symbol_ptr` of the symbol pointe to it
 
 Non_Lazy_Symbol_Ptr:
                      wait to do based on export_info and binding_info
 */

#if arch(arm64)
internal class FishHookChecker {
    
    static private func read_uleb128(p: inout UnsafePointer<UInt8>, end: UnsafePointer<UInt8>) -> UInt64 {
        var result: UInt64 = 0
        var bit = 0
        var read_next = true
        
        repeat {
            if p == end {
                assert(false, "malformed uleb128")
            }
            let slice = UInt64(p.pointee & 0x7f)
            if bit > 63 {
                assert(false, "uleb128 too big for uint64")
            } else {
                result |= (slice << bit)
                bit += 7
            }
            read_next = ((p.pointee & 0x80) >> 7) == 1
            p += 1
        } while (read_next)
        return result
    }
    
    @inline(__always)
    static func denyFishHook(_ symbol: String) {
        for i in 0..<_dyld_image_count() {
            if let image = _dyld_get_image_header(i) {
                denyFishHook(symbol, at: image, imageSlide: _dyld_get_image_vmaddr_slide(i))
            }
        }
        
    }

    @inline(__always)
    static func denyFishHook(_ symbol: String,
                             at image: UnsafePointer<mach_header>,
                             imageSlide slide: Int) {
        // Linked cmd
        let linkeditCmdName = SEG_LINKEDIT.data(using: String.Encoding.utf8)!.map({ $0 })
        var linkeditCmd: UnsafeMutablePointer<segment_command_64>!
        var dyldInfoCmd: UnsafeMutablePointer<dyld_info_command>!
        
        // Text cmd
        let textCmdName = SEG_TEXT.data(using: String.Encoding.utf8)!.map({ Int8($0) })
        var textCmd: UnsafeMutablePointer<segment_command_64>!
        
        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: image)+UInt(MemoryLayout<mach_header_64>.size)) else { return }
        
        for _ in 0..<image.pointee.ncmds {
            curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)
            
            if curCmd.pointee.cmd == LC_SEGMENT_64 {
                if (curCmd.pointee.segname.0 == linkeditCmdName[0] &&
                    curCmd.pointee.segname.1 == linkeditCmdName[1] &&
                    curCmd.pointee.segname.2 == linkeditCmdName[2] &&
                    curCmd.pointee.segname.3 == linkeditCmdName[3] &&
                    curCmd.pointee.segname.4 == linkeditCmdName[4] &&
                    curCmd.pointee.segname.5 == linkeditCmdName[5] &&
                    curCmd.pointee.segname.6 == linkeditCmdName[6] &&
                    curCmd.pointee.segname.7 == linkeditCmdName[7] &&
                    curCmd.pointee.segname.8 == linkeditCmdName[8] &&
                    curCmd.pointee.segname.9 == linkeditCmdName[9]) {
                    
                    linkeditCmd = curCmd
                }
                if (curCmd.pointee.segname.0 == textCmdName[0] &&
                    curCmd.pointee.segname.1 == textCmdName[1] &&
                    curCmd.pointee.segname.2 == textCmdName[2] &&
                    curCmd.pointee.segname.3 == textCmdName[3] &&
                    curCmd.pointee.segname.4 == textCmdName[4] &&
                    curCmd.pointee.segname.5 == textCmdName[5]) {
                    
                    textCmd = curCmd
                }
            } else if curCmd.pointee.cmd == LC_DYLD_INFO_ONLY || curCmd.pointee.cmd == LC_DYLD_INFO {
                dyldInfoCmd = UnsafeMutablePointer<dyld_info_command>(OpaquePointer(UnsafeRawPointer(curCmd)))
            }
        }
        
        if linkeditCmd == nil || dyldInfoCmd == nil || textCmd == nil { return }
        
        let linkeditBase = UInt64(slide) + linkeditCmd.pointee.vmaddr - linkeditCmd.pointee.fileoff
        let lazyBindInfoCmd = linkeditBase + UInt64(dyldInfoCmd.pointee.lazy_bind_off)
        
        rebindLazySymbol(symbol: symbol, image: image, imageSlide: slide, textCmd: textCmd, lazyBindInfoCmd: UnsafePointer<UInt8>(bitPattern: UInt(lazyBindInfoCmd)), lazyBindInfoSize: Int(dyldInfoCmd.pointee.lazy_bind_size))
    }

    // if symbol is LazySymbol
    // dyld_stub_binder => fastBindLazySymbol => doBindFastLazySymbol => ImageLoaderMachO::getLazyBindingInfo
    @inline(__always)
    private static func rebindLazySymbol(symbol: String,
                                   image: UnsafePointer<mach_header>,
                                   imageSlide slide: Int,
                                   textCmd: UnsafeMutablePointer<segment_command_64>,
                                   lazyBindInfoCmd: UnsafePointer<UInt8>!,
                                   lazyBindInfoSize: Int) {
        if lazyBindInfoCmd == nil {
            return
        }
        
        var stubHelperSection: UnsafeMutablePointer<section_64>!
        let stubHelperSectionName: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0x5f, 0x5f, 0x73, 0x74, 0x75, 0x62, 0x5f, 0x68, 0x65, 0x6c, 0x70, 0x65, 0x72, 0x00, 0x00, 0x00)
        
        for i in 0..<textCmd.pointee.nsects {
            let curSectionPointer = UnsafeRawPointer(textCmd).advanced(by: MemoryLayout<segment_command_64>.size + MemoryLayout<section_64>.size*Int(i))
            let curSection = UnsafeMutablePointer<section_64>(OpaquePointer(curSectionPointer))
            
            if curSection.pointee.sectname.0 == stubHelperSectionName.0 &&
                curSection.pointee.sectname.1 == stubHelperSectionName.1 &&
                curSection.pointee.sectname.2 == stubHelperSectionName.2 &&
                curSection.pointee.sectname.3 == stubHelperSectionName.3 &&
                curSection.pointee.sectname.4 == stubHelperSectionName.4 &&
                curSection.pointee.sectname.5 == stubHelperSectionName.5 &&
                curSection.pointee.sectname.6 == stubHelperSectionName.6 &&
                curSection.pointee.sectname.7 == stubHelperSectionName.7 &&
                curSection.pointee.sectname.8 == stubHelperSectionName.8 &&
                curSection.pointee.sectname.9 == stubHelperSectionName.9 &&
                curSection.pointee.sectname.10 == stubHelperSectionName.10 &&
                curSection.pointee.sectname.11 == stubHelperSectionName.11 &&
                curSection.pointee.sectname.12 == stubHelperSectionName.12 {
                
                stubHelperSection = curSection
                break
            }
        }
        
        // look for code of symbol_binder_code
        guard stubHelperSection != nil,
            let stubHelperVmAddr = UnsafeMutablePointer<UInt32>(bitPattern: slide+Int(stubHelperSection.pointee.addr)) else {
                return
            }
        
        // from begin of stub_helper to symbol_binder_code
        var codeOffset: Int!
        
        // 6 instructions: code of `br dyld_stub_binder`
        if stubHelperSection.pointee.size/4 <= 5 {
            return
        }
        let lazyBindingInfoStart = lazyBindInfoCmd!
        let lazyBindingInfoEnd = lazyBindInfoCmd! + lazyBindInfoSize
        
        for i in 5..<stubHelperSection.pointee.size/4 {
            /*  at C4.4.5 and C6.2.84 of ARM® Architecture Reference Manual
                ldr w16, #8 (.byte)
                b stub(br_dyld_stub_binder)
                .byte: symbol_bindInfo_offset
             */
            let instruction = stubHelperVmAddr.advanced(by: Int(i)).pointee
            // ldr wt
            let ldr = (instruction & (255 << 24)) >> 24
            let wt = instruction & (31 << 0)
            // #imm `00` sign = false
            let imm19 = (instruction & ((1 << 19 - 1) << 5)) >> 5
            
            // ldr w16, #8
            if ldr == 0b00011000 && wt == 16 && (imm19 << 2) == 8 {
                let bindingInfoOffset = stubHelperVmAddr.advanced(by: Int(i+2)).pointee  // .byte
                var p = lazyBindingInfoStart.advanced(by: Int(bindingInfoOffset))
                
                Label: while p <= lazyBindingInfoEnd  {
                    let opcode = Int32(p.pointee) & BIND_OPCODE_MASK
                    
                    switch opcode {
                    case BIND_OPCODE_DONE, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                        p += 1
                        continue Label
                    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                        p += 1
                        _ = read_uleb128(p: &p, end: lazyBindingInfoEnd)
                        continue Label
                    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                        p += 1
                        // _symbol
                        if String(cString: p + 1) == symbol {
                            codeOffset = Int(i)
                            break
                        }
                        while p.pointee != 0 {  // '\0'
                            p += 1
                        }
                        continue Label
                    case BIND_OPCODE_DO_BIND:
                        break Label
                    default:
                        p += 1
                        continue Label
                    }
                }
            }
        }
        
        if codeOffset == nil {
            return
        }
        
        let pointer = stubHelperVmAddr.advanced(by: (codeOffset))  // ldr w16 .byte
        let newMethod = UnsafeMutablePointer(pointer)
        var oldMethod: UnsafeMutableRawPointer? = nil
        FishHook.replaceSymbol(symbol, at: image, imageSlide: slide, newMethod: newMethod, oldMethod: &oldMethod)
    }
}


// MARK: - FishHook
fileprivate class FishHook {
    @inline(__always)
    fileprivate static func replaceSymbol(_ symbol: String,
                              at image: UnsafePointer<mach_header>,
                              imageSlide slide: Int,
                              newMethod: UnsafeMutableRawPointer,
                              oldMethod: inout UnsafeMutableRawPointer?)
    {
        replaceSymbolAtImage(image, imageSlide: slide, symbol: symbol, newMethod: newMethod, oldMethod: &oldMethod)
    }

    @inline(__always)
    private static func replaceSymbolAtImage(_ image: UnsafePointer<mach_header>,
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
    private static func replaceSymbolPointerAtSection(_ section: UnsafeMutablePointer<section_64>,
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
        
        for i in 0..<Int(section.pointee.size)/MemoryLayout<UnsafeMutableRawPointer>.size {
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
}
#endif
