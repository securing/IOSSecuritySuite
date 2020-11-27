//
//  FishHookChecker.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/24.
//  Copyright © 2020 wregula. All rights reserved.
//  https://github.com/TannerJin/anti-fishhook
//swiftlint:disable all

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
 
 
    .byte of the symbol is offset from beginning of lazy_binding_info to beginning of symbol_info
 
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
    
 
 
The `denyFishHook` will look for code of `symbol_binder_code` of the symbol, and then make `lazy_symbol_ptr` of the symbol pointee to it
 
 Non_Lazy_Symbol_Ptr:
                      wait to do based on export_info and binding_info
 */

#if arch(arm64)
internal class FishHookChecker {

    @inline(__always)
    static private func readUleb128(ptr: inout UnsafePointer<UInt8>, end: UnsafePointer<UInt8>) -> UInt64 {
        var result: UInt64 = 0
        var bit = 0
        var readNext = true

        repeat {
            if ptr == end {
                assert(false, "malformed uleb128")
            }
            let slice = UInt64(ptr.pointee & 0x7f)
            if bit > 63 {
                assert(false, "uleb128 too big for uint64")
            } else {
                result |= (slice << bit)
                bit += 7
            }
            readNext = ((ptr.pointee & 0x80) >> 7) == 1
            ptr += 1
        } while (readNext)
        return result
    }

    @inline(__always)
    static func denyFishHook(_ symbol: String) {
        for img in 0..<_dyld_image_count() {
            if let image = _dyld_get_image_header(img) {
                denyFishHook(symbol, at: image, imageSlide: _dyld_get_image_vmaddr_slide(img))
            }
        }

    }

    @inline(__always)
    static func denyFishHook(_ symbol: String,
                             at image: UnsafePointer<mach_header>,
                             imageSlide slide: Int) {
        // Linked cmd
        guard let linkeditCmdName = SEG_LINKEDIT.data(using: String.Encoding.utf8)?.map({ $0 }) else { return }
        var linkeditCmd: UnsafeMutablePointer<segment_command_64>!
        var dyldInfoCmd: UnsafeMutablePointer<dyld_info_command>!

        
        // Text cmd
        guard let textCmdName = SEG_TEXT.data(using: String.Encoding.utf8)?.map({ Int8($0) }) else { return }
        var textCmd: UnsafeMutablePointer<segment_command_64>!

        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: image)+UInt(MemoryLayout<mach_header_64>.size)) else { return }

        for _ in 0..<image.pointee.ncmds {
            curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)

            if curCmd.pointee.cmd == LC_SEGMENT_64 {
                if curCmd.pointee.segname.0 == linkeditCmdName[0] &&
                    curCmd.pointee.segname.1 == linkeditCmdName[1] &&
                    curCmd.pointee.segname.2 == linkeditCmdName[2] &&
                    curCmd.pointee.segname.3 == linkeditCmdName[3] &&
                    curCmd.pointee.segname.4 == linkeditCmdName[4] &&
                    curCmd.pointee.segname.5 == linkeditCmdName[5] &&
                    curCmd.pointee.segname.6 == linkeditCmdName[6] &&
                    curCmd.pointee.segname.7 == linkeditCmdName[7] &&
                    curCmd.pointee.segname.8 == linkeditCmdName[8] &&
                    curCmd.pointee.segname.9 == linkeditCmdName[9] {

                    linkeditCmd = curCmd
                }
                if curCmd.pointee.segname.0 == textCmdName[0] &&
                    curCmd.pointee.segname.1 == textCmdName[1] &&
                    curCmd.pointee.segname.2 == textCmdName[2] &&
                    curCmd.pointee.segname.3 == textCmdName[3] &&
                    curCmd.pointee.segname.4 == textCmdName[4] &&
                    curCmd.pointee.segname.5 == textCmdName[5] {

                    textCmd = curCmd
                }
            } else if curCmd.pointee.cmd == LC_DYLD_INFO_ONLY || curCmd.pointee.cmd == LC_DYLD_INFO {
                dyldInfoCmd = UnsafeMutablePointer<dyld_info_command>(OpaquePointer(UnsafeRawPointer(curCmd)))
            }
        }

        if linkeditCmd == nil || dyldInfoCmd == nil || textCmd == nil { return }

        let linkeditBase = UInt64(slide + Int(linkeditCmd.pointee.vmaddr) - Int(linkeditCmd.pointee.fileoff))
        let lazyBindInfoCmd = linkeditBase + UInt64(dyldInfoCmd.pointee.lazy_bind_off)
        // swiftlint:disable:next line_length
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
        // swiftlint:disable:next line_length
        let stubHelperSectionName: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0x5f, 0x5f, 0x73, 0x74, 0x75, 0x62, 0x5f, 0x68, 0x65, 0x6c, 0x70, 0x65, 0x72, 0x00, 0x00, 0x00)

        for tmp in 0..<textCmd.pointee.nsects {
            let curSectionPointer = UnsafeRawPointer(textCmd).advanced(by: MemoryLayout<segment_command_64>.size + MemoryLayout<section_64>.size*Int(tmp))
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

        for tmp in 5..<stubHelperSection.pointee.size/4 {
            /*  at C4.4.5 and C6.2.84 of ARM® Architecture Reference Manual
                ldr w16, #8 (.byte)
                b stub(br_dyld_stub_binder)
                .byte: symbol_bindInfo_offset
             */
            let instruction = stubHelperVmAddr.advanced(by: Int(tmp)).pointee
            // ldr wt
            let ldr = (instruction & (255 << 24)) >> 24
            let wt = instruction & (31 << 0)
            // #imm `00` sign = false
            let imm19 = (instruction & ((1 << 19 - 1) << 5)) >> 5

            // ldr w16, #8
            if ldr == 0b00011000 && wt == 16 && (imm19 << 2) == 8 {
                let bindingInfoOffset = stubHelperVmAddr.advanced(by: Int(tmp+2)).pointee  // .byte
                var ptr = lazyBindingInfoStart.advanced(by: Int(bindingInfoOffset))

                Label: while ptr <= lazyBindingInfoEnd {
                    let opcode = Int32(ptr.pointee) & BIND_OPCODE_MASK

                    switch opcode {
                    case BIND_OPCODE_DONE, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                        ptr += 1
                        continue Label
                    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                        ptr += 1
                        _ = readUleb128(ptr: &ptr, end: lazyBindingInfoEnd)
                        continue Label
                    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                        ptr += 1
                        // _symbol
                        if String(cString: ptr + 1) == symbol {
                            codeOffset = Int(tmp)
                            break
                        }
                        while ptr.pointee != 0 {  // '\0'
                            ptr += 1
                        }
                        continue Label
                    case BIND_OPCODE_DO_BIND:
                        break Label
                    default:
                        ptr += 1
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
        var oldMethod: UnsafeMutableRawPointer?
        FishHook.replaceSymbol(symbol, at: image, imageSlide: slide, newMethod: newMethod, oldMethod: &oldMethod)
    }
}

// MARK: - FishHook
private class FishHook {
    @inline(__always)
    fileprivate static func replaceSymbol(_ symbol: String,
                                          at image: UnsafePointer<mach_header>,
                                          imageSlide slide: Int,
                                          newMethod: UnsafeMutableRawPointer,
                                          oldMethod: inout UnsafeMutableRawPointer?) {
        replaceSymbolAtImage(image, imageSlide: slide, symbol: symbol, newMethod: newMethod, oldMethod: &oldMethod)
    }

    @inline(__always)
    private static func replaceSymbolAtImage(_ image: UnsafePointer<mach_header>,
                                             imageSlide slide: Int,
                                             symbol: String,
                                             newMethod: UnsafeMutableRawPointer,
                                             oldMethod: inout UnsafeMutableRawPointer?) {
        // __Linkedit cmd
        var linkeditCmd: UnsafeMutablePointer<segment_command_64>!
        let linkeditName = SEG_LINKEDIT.data(using: String.Encoding.utf8)!.map({ $0 })

        // Symbol cmd
        var symtabCmd: UnsafeMutablePointer<symtab_command>!
        var dynamicSymtabCmd: UnsafeMutablePointer<dysymtab_command>!

        // __Data cmd
        var dataCmd: UnsafeMutablePointer<segment_command_64>!
        let segData = SEG_DATA.data(using: String.Encoding.utf8)!.map({ Int8($0) }) 

        guard var curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: UInt(bitPattern: image)+UInt(MemoryLayout<mach_header_64>.size)) else { return }

        for _ in 0..<image.pointee.ncmds {
            curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: segment_command_64.self)

            if curCmd.pointee.cmd == LC_SEGMENT_64 {
                if UInt8(curCmd.pointee.segname.0) == linkeditName[0] &&
                    UInt8(curCmd.pointee.segname.1) == linkeditName[1] &&
                    UInt8(curCmd.pointee.segname.2) == linkeditName[2] &&
                    UInt8(curCmd.pointee.segname.3) == linkeditName[3] &&
                    UInt8(curCmd.pointee.segname.4) == linkeditName[4] &&
                    UInt8(curCmd.pointee.segname.5) == linkeditName[5] &&
                    UInt8(curCmd.pointee.segname.6) == linkeditName[6] &&
                    UInt8(curCmd.pointee.segname.7) == linkeditName[7] &&
                    UInt8(curCmd.pointee.segname.8) == linkeditName[8] &&
                    UInt8(curCmd.pointee.segname.9) == linkeditName[9] {

                    linkeditCmd = curCmd
                }
                if curCmd.pointee.segname.0 == segData[0] &&
                    curCmd.pointee.segname.1 == segData[1] &&
                    curCmd.pointee.segname.2 == segData[2] &&
                    curCmd.pointee.segname.3 == segData[3] &&
                    curCmd.pointee.segname.4 == segData[4] &&
                    curCmd.pointee.segname.5 == segData[5] {

                    dataCmd = curCmd
                }

            } else if curCmd.pointee.cmd == LC_SYMTAB {
                symtabCmd = UnsafeMutablePointer<symtab_command>(OpaquePointer(curCmd))
            } else if curCmd.pointee.cmd == LC_DYSYMTAB {
                dynamicSymtabCmd = UnsafeMutablePointer<dysymtab_command>(OpaquePointer(curCmd))
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

        for tmp in 0..<dataCmd.pointee.nsects {
            let curSection = UnsafeMutableRawPointer(dataCmd).advanced(by: MemoryLayout<segment_command_64>.size + MemoryLayout<section_64>.size*Int(tmp)).assumingMemoryBound(to: section_64.self)

            // symbol_pointers sections
            if curSection.pointee.flags == S_LAZY_SYMBOL_POINTERS {
                replaceSymbolPointerAtSection(curSection, symtab: symtab!, strtab: strtab!, indirectsym: indirectsym!, slide: slide, symbolName: symbol, newMethod: newMethod, oldMethod: &oldMethod)
            }
            if curSection.pointee.flags == S_NON_LAZY_SYMBOL_POINTERS {
                replaceSymbolPointerAtSection(curSection, symtab: symtab!, strtab: strtab!, indirectsym: indirectsym!, slide: slide, symbolName: symbol, newMethod: newMethod, oldMethod: &oldMethod)
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
                                                      oldMethod: inout UnsafeMutableRawPointer?) {
        let indirectSymVmAddr = indirectsym.advanced(by: Int(section.pointee.reserved1))
        let sectionVmAddr = UnsafeMutablePointer<UnsafeMutableRawPointer>(bitPattern: slide+Int(section.pointee.addr))

        if sectionVmAddr == nil {
            return
        }

        for tmp in 0..<Int(section.pointee.size)/MemoryLayout<UnsafeMutableRawPointer>.size {
            let curIndirectSym = indirectSymVmAddr.advanced(by: tmp)
            if curIndirectSym.pointee == INDIRECT_SYMBOL_ABS || curIndirectSym.pointee == INDIRECT_SYMBOL_LOCAL {
                continue
            }
            let curStrTabOff = symtab.advanced(by: Int(curIndirectSym.pointee)).pointee.n_un.n_strx
            let curSymbolName = strtab.advanced(by: Int(curStrTabOff+1))

            if String(cString: curSymbolName) == symbolName {
                oldMethod = sectionVmAddr!.advanced(by: tmp).pointee
                
                // iOS 13, dyld2 has been updated dyld3, LAZY_SYMBOL_POINTERS binding is different from dyld2 without Debug
                if #available(iOS 13, *) {
                    // -2: RTLD_DEFAULT
                    if let symbolPointer = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbolName.cString(using: .utf8)) {
                        sectionVmAddr!.advanced(by: tmp).initialize(to: symbolPointer)
                    }
                } else {
                    sectionVmAddr!.advanced(by: tmp).initialize(to: newMethod)
                }
                break
            }
        }
    }
}
#endif
