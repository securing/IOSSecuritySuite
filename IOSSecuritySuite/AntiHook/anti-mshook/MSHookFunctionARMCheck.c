//
//  MSHookFunctionARMCheck.c
//  AntiMSHook
//
//  Created by jintao on 2019/9/18.
//  Copyright © 2019 jintao. All rights reserved.
//

#include "MSHookFunctionARMCheck.h"

__attribute__ ((always_inline))
_Bool MSHookARMCheck(void *symbol_addr) {
    uint32_t *arms = (uint32_t *)symbol_addr;
    
    uint32_t first_instruction = *arms;
    uint32_t second_instruction = *(arms+1);
    
    // http://armconverter.com/ to test

    /*  ldr rd [rn #im]      ARM Architecture Reference Manual A4.1.23
     
        31         28 27    26 25  24  23  22  21  20  19        16 15        12 11                      0
        +------------+--------+---+---+---+---+---+---+------------+------------+------------------------+
        |    cond    | 0    1 | I | P | U | 0 | W | 1 |     Rn     |    Rd      |       addr_mode        |
        +------------+--------+---+---+---+---+---+---+------------+------------+------------------------+
     */

    
    /*   Load/store immediate offset (I = 0)
                                                   11         0
         +----------------------------------------------------+
         |cond | 010 | P | U | B | W | L | Rn | Rd | immediate|
         +----------------------------------------------------+
     */
    
    
    /*   Load/store  multiple
     
                    25
         +-----------------------------------------------------------------------+
         |cond | 100 | P | U | S | W | L | Rn |         register list            |
         +-----------------------------------------------------------------------+
     
         ldr x16, #8       (50 00 00 58; 0x58000050)
         0101 100 0 0 0 0 0 0000 0000 0000 010 10000
     
         If R15 is specified as register Rn, the value used is the address of the instruction plus eight.
     */

    int ldr = (first_instruction & (7 << 25)) >> 25;
    int x16 = first_instruction & (31 << 0);
    
    _Bool ldr_x16 = 0;
    
    // 100 && x16
    if ((ldr == 4) && (x16 = 16)) {
        ldr_x16 = 1;
    }
    
    
    /*   Load/store register offset (I = 1)
    
                   25                   19      16 15    12 11              7 6     5 4 3      0
         +-------------------------------------------------------------------------------------+
         |cond | 011 | P | U | B | W | L |   Rn   |   Rd   |   shit amount   | shit | 0 |  Rm  |
         +-------------------------------------------------------------------------------------+
     
         ldr r15 [x16 #0]     (r15 = pc)
     
         br x16       (00021FD6; 0xD61F0200)
         1101 011 0 0 0 0 1 1111 00000010000 0 0000
     
         If R15 is specified as register Rn, the value used is the address of the instruction plus eight.
     */
    
    int br_ldr = (second_instruction & (7 << 25)) >> 25;
    int br_ldr_r15 = (second_instruction & (15 << 16)) >> 16;
    int br_ldr_x16 = (second_instruction & (127 << 5)) >> 5;
    
    _Bool br_x16 = 0;
    
    // 011 && pc && x16
    if ((br_ldr == 3) && (br_ldr_r15 == 15) && (br_ldr_x16 == 16)) {
        br_x16 = 1;
    }
    
    return ldr_x16 && br_x16;
}
