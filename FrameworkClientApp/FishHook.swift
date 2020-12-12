//
//  FishHook.swift
//  FishHookProtect
//
//  Created by jintao on 2019/3/28.
//  Copyright © 2019 jintao. All rights reserved.
//
// swiftlint:disable all

import Foundation
import MachO

#if arch(arm64)
@inline(__always)  // just for Swift
public func replaceSymbol(_ symbol: String,
                          newMethod: UnsafeMutableRawPointer,
                          oldMethod: inout UnsafeMutableRawPointer?)
{
    for i in 0..<_dyld_image_count() {
        if let image = _dyld_get_image_header(i) {
            replaceSymbol(symbol, at: image, imageSlide: _dyld_get_image_vmaddr_slide(i), newMethod: newMethod, oldMethod: &oldMethod)
        }
    }
}

private func replaceSymbol(_ symbol: String,
                                      at image: UnsafePointer<mach_header>,
                                      imageSlide slide: Int,
                                      newMethod: UnsafeMutableRawPointer,
                                      oldMethod: inout UnsafeMutableRawPointer?) {
    replaceSymbolAtImage(image, imageSlide: slide, symbol: symbol, newMethod: newMethod, oldMethod: &oldMethod)
}

@inline(__always)
private func replaceSymbolAtImage(_ image: UnsafePointer<mach_header>,
                                         imageSlide slide: Int,
                                         symbol: String,
                                         newMethod: UnsafeMutableRawPointer,
                                         oldMethod: inout UnsafeMutableRawPointer?) {
    var linkeditCmd: UnsafeMutablePointer<segment_command_64>!
    var dataCmd: UnsafeMutablePointer<segment_command_64>!
    var symtabCmd: UnsafeMutablePointer<symtab_command>!
    var dynamicSymtabCmd: UnsafeMutablePointer<dysymtab_command>!

    guard var curCmdPointer = UnsafeMutableRawPointer(bitPattern: UInt(bitPattern: image)+UInt(MemoryLayout<mach_header_64>.size)) else { return }
    
    for _ in 0..<image.pointee.ncmds {
        let curCmd = curCmdPointer.assumingMemoryBound(to: segment_command_64.self)

        if curCmd.pointee.cmd == LC_SEGMENT_64 {
            let curCmdNameOffset = MemoryLayout.size(ofValue: curCmd.pointee.cmd) + MemoryLayout.size(ofValue: curCmd.pointee.cmdsize)
            let curCmdNamePointer = curCmdPointer.advanced(by: curCmdNameOffset).assumingMemoryBound(to: Int8.self)
            let curCmdName = String(cString: curCmdNamePointer)
            if (curCmdName == SEG_LINKEDIT) {
                linkeditCmd = curCmd
            } else if (curCmdName == SEG_DATA) {
                dataCmd = curCmd
            }
        } else if curCmd.pointee.cmd == LC_SYMTAB {
            symtabCmd = UnsafeMutablePointer<symtab_command>(OpaquePointer(curCmd))
        } else if curCmd.pointee.cmd == LC_DYSYMTAB {
            dynamicSymtabCmd = UnsafeMutablePointer<dysymtab_command>(OpaquePointer(curCmd))
        }
        
        curCmdPointer += Int(curCmd.pointee.cmdsize)
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
private func replaceSymbolPointerAtSection(_ section: UnsafeMutablePointer<section_64>,
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
            sectionVmAddr!.advanced(by: tmp).initialize(to: newMethod)
            break
        }
    }
}
#endif
