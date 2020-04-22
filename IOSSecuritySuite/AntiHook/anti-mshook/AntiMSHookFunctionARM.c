//
//  AntiMSHook.c
//  AntiMSHook
//
//  Created by jintao on 2019/9/17.
//  Copyright © 2019 jintao. All rights reserved.
//

#include "AntiMSHookFunctionARM.h"
#import "MSHookFunctionARMCheck.h"
#import <mach/mach_init.h>
#import <mach/vm_map.h>


// (xnu vm feature): mmap ==> vm_region
__attribute__ ((always_inline))
void* antiMSHook(void* orig_func) {
    if (!MSHookARMCheck(orig_func)) { return NULL; }
    
    // 16: replaced instructions
    uint64_t func_begin = (uint64_t)(orig_func+16);
    
    vm_region_basic_info_data_64_t info;
    vm_address_t region_address = 1;
    vm_size_t size;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;
    
//    resetSymbol("vm_region_64");  antiFishhook
    while (1) {
        if (region_address == 0) {
            return NULL;
        }
        
        kern_return_t kr = vm_region_64(mach_task_self_, &region_address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object_name);
        
        if (kr == KERN_SUCCESS) {
            if (info.protection == (VM_PROT_READ|VM_PROT_EXECUTE)) {
                // mshook do not handle `pc` offset
                uint64_t* _func_begin = (uint64_t *)(region_address+16+8);  // 16: replaced instructions;  8: extra jump instructions
                if (*_func_begin == func_begin) {
                    return (void *)(region_address);
                }
                
                // mshook handle `pc` offset
                int max_buffer_instructions_count = 20;   // 8 ~ 18
                
                for (int i = 0; i<max_buffer_instructions_count; i++) {
                    uint64_t* cur_instruction_addr = (uint64_t *)(region_address+i*4);
                    if (MSHookARMCheck(cur_instruction_addr) && (*(cur_instruction_addr+1) == func_begin)) {
                        return (void *)region_address;
                    }
                }
            }
            region_address += size;
        } else {
            return NULL;
        }
    }
    
    return NULL;
}



