#!/usr/bin/env python
'''

PS4 Kernel Loader by SocraticBliss (R)

Major Thanks to...
# aerosoul
# balika011
# Znullptr
# Pablo (kozarovv)
# ChendoChap
# xyz
# CelesteBlue
# kiwidogg
# motoharu
# noname120
# flatz
# Team Reswitched

Extra Special Thanks for telling me my program sucks...
# zecoxao

ps4_kernel.py: IDA loader for reading Sony PlayStation(R) 4 Kernel files

'''

from idaapi import *
from idc import *

import idaapi
import idc
import operator
import struct

class Binary:

    __slots__ = ('EI_MAGIC', 'EI_CLASS', 'EI_DATA', 'EI_VERSION',
                 'EI_OSABI', 'EI_PADDING', 'EI_ABIVERSION', 'EI_SIZE',
                 'E_TYPE', 'E_MACHINE', 'E_VERSION', 'E_START_ADDR',
                 'E_PHT_OFFSET', 'E_SHT_OFFSET', 'E_FLAGS', 'E_SIZE',
                 'E_PHT_SIZE', 'E_PHT_COUNT', 'E_SHT_SIZE', 'E_SHT_COUNT',
                 'E_SHT_INDEX', 'E_SEGMENTS', 'E_SECTIONS')
    
    # Elf Types
    ET_NONE                   = 0x0
    ET_REL                    = 0x1
    ET_EXEC                   = 0x2
    ET_DYN                    = 0x3
    ET_CORE                   = 0x4
    ET_SCE_EXEC               = 0xfe00
    ET_SCE_REPLAY_EXEC        = 0xfe01
    ET_SCE_RELEXEC            = 0xfe04
    ET_SCE_STUBLIB            = 0xfe0c
    ET_SCE_DYNEXEC            = 0xfe10
    ET_SCE_DYNAMIC            = 0xfe18
    ET_LOPROC                 = 0xff00
    ET_HIPROC                 = 0xffff
    
    # Elf Architecture
    EM_X86_64                 = 0x3e
    
    def __init__(self, f):
    
        f.seek(0)
        
        self.EI_MAGIC         = struct.unpack('4s', f.read(4))[0]
        self.EI_CLASS         = struct.unpack('<B', f.read(1))[0]
        self.EI_DATA          = struct.unpack('<B', f.read(1))[0]
        self.EI_VERSION       = struct.unpack('<B', f.read(1))[0]
        self.EI_OSABI         = struct.unpack('<B', f.read(1))[0]
        self.EI_ABIVERSION    = struct.unpack('<B', f.read(1))[0]
        self.EI_PADDING       = struct.unpack('6x', f.read(6))
        self.EI_SIZE          = struct.unpack('<B', f.read(1))[0]
        
        # Elf Properties
        self.E_TYPE           = struct.unpack('<H', f.read(2))[0]
        self.E_MACHINE        = struct.unpack('<H', f.read(2))[0]
        self.E_VERSION        = struct.unpack('<I', f.read(4))[0]
        self.E_START_ADDR     = struct.unpack('<Q', f.read(8))[0]
        self.E_PHT_OFFSET     = struct.unpack('<Q', f.read(8))[0]
        self.E_SHT_OFFSET     = struct.unpack('<Q', f.read(8))[0]
        self.E_FLAGS          = struct.unpack('<I', f.read(4))[0]
        self.E_SIZE           = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_SIZE       = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_COUNT      = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_SIZE       = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_COUNT      = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_INDEX      = struct.unpack('<H', f.read(2))[0]
        
        # Prevent Other Binaries
        if self.E_MACHINE != Binary.EM_X86_64:
            return None
        
        try:
            f.seek(self.E_PHT_OFFSET)
        except:
            return None
        
        # Elf Program Header Table
        Binary.E_SEGMENTS = [Segment(f) for entry in range(self.E_PHT_COUNT)]
        
        try:
            f.seek(self.E_SHT_OFFSET)
        except:
            return None
        
        # Elf Section Header Table
        Binary.E_SECTIONS = [Section(f) for entry in range(self.E_SHT_COUNT)]
    
    def procomp(self, processor, pointer, til):
    
        # Processor Type
        idc.set_processor_type(processor, SETPROC_LOADER)
        
        # Compiler Attributes
        idc.set_inf_attr(INF_COMPILER, COMP_GNU)
        idc.set_inf_attr(INF_MODEL, pointer)
        idc.set_inf_attr(INF_SIZEOF_BOOL, 0x1)
        idc.set_inf_attr(INF_SIZEOF_LONG, 0x8)
        idc.set_inf_attr(INF_SIZEOF_LDBL, 0x10)
        
        # Type Library
        idc.add_default_til(til)
        
        # Loader Flags
        #idc.set_inf_attr(INF_LFLAGS, LFLG_64BIT)
        
        # Assume GCC3 Names
        idc.set_inf_attr(INF_DEMNAMES, DEMNAM_GCC3 | DEMNAM_NAME)
        
        # File Type
        idc.set_inf_attr(INF_FILETYPE, FT_ELF)
        
        # Analysis Flags
        # (unchecked) Delete instructions with no xrefs
        # (unchecked) Coagulate data segments in the final pass
        idc.set_inf_attr(INF_AF, 0xDFFFFFDF)
        
        # Return Bitsize
        return self.EI_CLASS
    

class Segment:

    __slots__ = ('TYPE', 'FLAGS', 'OFFSET', 'MEM_ADDR',
                 'FILE_ADDR', 'FILE_SIZE', 'MEM_SIZE', 'ALIGNMENT')
    
    # Segment Types
    PT_NULL                = 0x0
    PT_LOAD                = 0x1
    PT_DYNAMIC             = 0x2
    PT_INTERP              = 0x3
    PT_NOTE                = 0x4
    PT_SHLIB               = 0x5
    PT_PHDR                = 0x6
    PT_TLS                 = 0x7
    PT_NUM                 = 0x8
    PT_SCE_DYNLIBDATA      = 0x61000000
    PT_SCE_PROCPARAM       = 0x61000001
    PT_SCE_MODULEPARAM     = 0x61000002
    PT_SCE_RELRO           = 0x61000010
    PT_GNU_EH_FRAME        = 0x6474e550
    PT_GNU_STACK           = 0x6474e551
    PT_SCE_COMMENT         = 0x6fffff00
    PT_SCE_LIBVERSION      = 0x6fffff01
    PT_HIOS                = 0x6fffffff
    PT_LOPROC              = 0x70000000
    PT_SCE_SEGSYM          = 0x700000A8
    PT_HIPROC              = 0x7fffffff
    
    # Segment Alignments
    AL_NONE                = 0x0
    AL_BYTE                = 0x1
    AL_WORD                = 0x2
    AL_DWORD               = 0x4
    AL_QWORD               = 0x8
    AL_PARA                = 0x10
    AL_4K                  = 0x4000
    
    def __init__(self, f):
    
        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<I', f.read(4))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.FILE_ADDR = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.MEM_SIZE  = struct.unpack('<Q', f.read(8))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]
    
    def alignment(self):
    
        return {
            Segment.AL_NONE            : saAbs,
            Segment.AL_BYTE            : saRelByte,
            Segment.AL_WORD            : saRelWord,
            Segment.AL_DWORD           : saRelDble,
            Segment.AL_QWORD           : saRelQword,
            Segment.AL_PARA            : saRelPara,
            Segment.AL_4K              : saRel4K,
        }.get(self.ALIGNMENT, saRel_MAX_ALIGN_CODE)
    
    def flags(self):
    
        return self.FLAGS & 0xF
    
    def name(self):
    
        return {
            Segment.PT_NULL            : 'NULL',
            Segment.PT_LOAD            : 'CODE' if self.flags() == (SEGPERM_EXEC | SEGPERM_READ) else 'DATA',
            Segment.PT_DYNAMIC         : 'DYNAMIC',
            Segment.PT_INTERP          : 'INTERP',
            Segment.PT_NOTE            : 'NOTE',
            Segment.PT_SHLIB           : 'SHLIB',
            Segment.PT_PHDR            : 'PHDR',
            Segment.PT_TLS             : 'TLS',
            Segment.PT_NUM             : 'NUM',
            Segment.PT_SCE_DYNLIBDATA  : 'SCE_DYNLIBDATA',
            Segment.PT_SCE_PROCPARAM   : 'SCE_PROCPARAM',
            Segment.PT_SCE_MODULEPARAM : 'SCE_MODULEPARAM',
            Segment.PT_SCE_RELRO       : 'SCE_RELRO',
            Segment.PT_GNU_EH_FRAME    : 'GNU_EH_FRAME',
            Segment.PT_GNU_STACK       : 'GNU_STACK',
            Segment.PT_SCE_COMMENT     : 'SCE_COMMENT',
            Segment.PT_SCE_LIBVERSION  : 'SCE_LIBVERSION',
        }.get(self.TYPE, 'UNK')
    
    def struct(self, name, members, location = 0x0):
    
        if self.FLAGS > 7:
            return idc.get_struc_id(name)
        
        entry = idc.add_struc(BADADDR, name, False)
        
        for (member, comment, size) in members:
            flags = idaapi.get_flags_by_size(size)
            
            if member in ['function', 'offset', 'd_name']:
                idc.add_struc_member(entry, member, location, flags + FF_0OFF, BADADDR, size, BADADDR, 0, REF_OFF64)
            else:
                idc.add_struc_member(entry, member, location, flags, BADADDR, size)
            
            idc.set_member_cmt(entry, location, comment, False)
            location += size
        
        return entry
    
    def type(self):
    
        return {
            Segment.PT_LOAD            : 'CODE' if self.flags() == (SEGPERM_EXEC | SEGPERM_READ) else 'DATA',
            Segment.PT_DYNAMIC         : 'DATA',
            Segment.PT_INTERP          : 'CONST',
            Segment.PT_NOTE            : 'CONST',
            Segment.PT_PHDR            : 'CONST',
            Segment.PT_TLS             : 'BSS',
            Segment.PT_SCE_DYNLIBDATA  : 'CONST',
            Segment.PT_SCE_PROCPARAM   : 'DATA',
            Segment.PT_SCE_MODULEPARAM : 'CONST',
            Segment.PT_SCE_RELRO       : 'DATA',
            Segment.PT_GNU_EH_FRAME    : 'CONST',
            Segment.PT_SCE_COMMENT     : 'CONST',
            Segment.PT_SCE_LIBVERSION  : 'CONST',
        }.get(self.TYPE, 'UNK')
    

class Section:

    __slots__ = ('NAME', 'TYPE', 'FLAGS', 'MEM_ADDR',
                 'OFFSET', 'FILE_SIZE', 'LINK', 'INFO',
                 'ALIGNMENT', 'FSE_SIZE')
    
    def __init__(self, f):
    
        self.NAME      = struct.unpack('<I', f.read(4))[0]
        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.LINK      = struct.unpack('<I', f.read(4))[0]
        self.INFO      = struct.unpack('<I', f.read(4))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]
        self.FSE_SIZE  = struct.unpack('<Q', f.read(8))[0]
    

class Dynamic:

    __slots__ = ('TAG', 'VALUE', 'ID', 'VERSION_MAJOR', 'VERSION_MINOR', 'INDEX')
    
    # Dynamic Tags
    (DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
    DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI,
    DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL, DT_RELSZ, DT_RELENT, DT_PLTREL,
    DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY, DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS, DT_ENCODING, DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ)         = range(0x22)
    DT_SCE_IDTABENTSZ           = 0x61000005
    DT_SCE_FINGERPRINT          = 0x61000007
    DT_SCE_ORIGINAL_FILENAME    = 0x61000009
    DT_SCE_MODULE_INFO          = 0x6100000d
    DT_SCE_NEEDED_MODULE        = 0x6100000f
    DT_SCE_MODULE_ATTR          = 0x61000011
    DT_SCE_EXPORT_LIB           = 0x61000013
    DT_SCE_IMPORT_LIB           = 0x61000015
    DT_SCE_EXPORT_LIB_ATTR      = 0x61000017
    DT_SCE_IMPORT_LIB_ATTR      = 0x61000019
    DT_SCE_STUB_MODULE_NAME     = 0x6100001d
    DT_SCE_STUB_MODULE_VERSION  = 0x6100001f
    DT_SCE_STUB_LIBRARY_NAME    = 0x61000021
    DT_SCE_STUB_LIBRARY_VERSION = 0x61000023
    DT_SCE_HASH                 = 0x61000025
    DT_SCE_PLTGOT               = 0x61000027
    DT_SCE_JMPREL               = 0x61000029
    DT_SCE_PLTREL               = 0x6100002b
    DT_SCE_PLTRELSZ             = 0x6100002d
    DT_SCE_RELA                 = 0x6100002f
    DT_SCE_RELASZ               = 0x61000031
    DT_SCE_RELAENT              = 0x61000033
    DT_SCE_STRTAB               = 0x61000035
    DT_SCE_STRSZ                = 0x61000037
    DT_SCE_SYMTAB               = 0x61000039
    DT_SCE_SYMENT               = 0x6100003b
    DT_SCE_HASHSZ               = 0x6100003d
    DT_SCE_SYMTABSZ             = 0x6100003f
    DT_SCE_HIOS                 = 0x6ffff000
    DT_GNU_HASH                 = 0x6ffffef5
    DT_VERSYM                   = 0x6ffffff0
    DT_RELACOUNT                = 0x6ffffff9
    DT_RELCOUNT                 = 0x6ffffffa
    DT_FLAGS_1                  = 0x6ffffffb
    DT_VERDEF                   = 0x6ffffffc
    DT_VERDEFNUM                = 0x6ffffffd
    
    def __init__(self, f):
        
        self.TAG   = struct.unpack('<Q', f.read(8))[0]
        self.VALUE = struct.unpack('<Q', f.read(8))[0]
    
    def tag(self):
    
        return {
            Dynamic.DT_NULL                     : 'DT_NULL',
            Dynamic.DT_NEEDED                   : 'DT_NEEDED',
            Dynamic.DT_PLTRELSZ                 : 'DT_PLTRELSZ',
            Dynamic.DT_PLTGOT                   : 'DT_PLTGOT',
            Dynamic.DT_HASH                     : 'DT_HASH',
            Dynamic.DT_STRTAB                   : 'DT_STRTAB',
            Dynamic.DT_SYMTAB                   : 'DT_SYMTAB',
            Dynamic.DT_RELA                     : 'DT_RELA',
            Dynamic.DT_RELASZ                   : 'DT_RELASZ',
            Dynamic.DT_RELAENT                  : 'DT_RELAENT',
            Dynamic.DT_STRSZ                    : 'DT_STRSZ',
            Dynamic.DT_SYMENT                   : 'DT_SYMENT',
            Dynamic.DT_INIT                     : 'DT_INIT',
            Dynamic.DT_FINI                     : 'DT_FINI',
            Dynamic.DT_SONAME                   : 'DT_SONAME',
            Dynamic.DT_RPATH                    : 'DT_RPATH',
            Dynamic.DT_SYMBOLIC                 : 'DT_SYMBOLIC',
            Dynamic.DT_REL                      : 'DT_REL',
            Dynamic.DT_RELSZ                    : 'DT_RELSZ',
            Dynamic.DT_RELENT                   : 'DT_RELENT',
            Dynamic.DT_PLTREL                   : 'DT_PLTREL',
            Dynamic.DT_DEBUG                    : 'DT_DEBUG',
            Dynamic.DT_TEXTREL                  : 'DT_TEXTREL',
            Dynamic.DT_JMPREL                   : 'DT_JMPREL',
            Dynamic.DT_BIND_NOW                 : 'DT_BIND_NOW',
            Dynamic.DT_INIT_ARRAY               : 'DT_INIT_ARRAY',
            Dynamic.DT_FINI_ARRAY               : 'DT_FINI_ARRAY',
            Dynamic.DT_INIT_ARRAYSZ             : 'DT_INIT_ARRAYSZ',
            Dynamic.DT_FINI_ARRAYSZ             : 'DT_FINI_ARRAYSZ',
            Dynamic.DT_RUNPATH                  : 'DT_RUN_PATH',
            Dynamic.DT_FLAGS                    : 'DT_FLAGS',
            Dynamic.DT_ENCODING                 : 'DT_ENCODING',
            Dynamic.DT_PREINIT_ARRAY            : 'DT_PREINIT_ARRAY',
            Dynamic.DT_PREINIT_ARRAYSZ          : 'DT_PREINIT_ARRAYSZ',
            Dynamic.DT_SCE_IDTABENTSZ           : 'DT_SCE_IDTABENTSZ',
            Dynamic.DT_SCE_FINGERPRINT          : 'DT_SCE_FINGERPRINT',
            Dynamic.DT_SCE_ORIGINAL_FILENAME    : 'DT_SCE_ORIGINAL_FILENAME',
            Dynamic.DT_SCE_MODULE_INFO          : 'DT_SCE_MODULE_INFO',
            Dynamic.DT_SCE_NEEDED_MODULE        : 'DT_SCE_NEEDED_MODULE',
            Dynamic.DT_SCE_MODULE_ATTR          : 'DT_SCE_MODULE_ATTR',
            Dynamic.DT_SCE_EXPORT_LIB           : 'DT_SCE_EXPORT_LIB',
            Dynamic.DT_SCE_IMPORT_LIB           : 'DT_SCE_IMPORT_LIB',
            Dynamic.DT_SCE_EXPORT_LIB_ATTR      : 'DT_SCE_EXPORT_LIB_ATTR',
            Dynamic.DT_SCE_IMPORT_LIB_ATTR      : 'DT_SCE_IMPORT_LIB_ATTR',
            Dynamic.DT_SCE_STUB_MODULE_NAME     : 'DT_SCE_STUB_MODULE_NAME',
            Dynamic.DT_SCE_STUB_MODULE_VERSION  : 'DT_SCE_STUB_MODULE_VERSION',
            Dynamic.DT_SCE_STUB_LIBRARY_NAME    : 'DT_SCE_STUB_LIBRARY_NAME',
            Dynamic.DT_SCE_STUB_LIBRARY_VERSION : 'DT_SCE_STUB_LIBRARY_VERSION',
            Dynamic.DT_SCE_HASH                 : 'DT_SCE_HASH',
            Dynamic.DT_SCE_PLTGOT               : 'DT_SCE_PLTGOT',
            Dynamic.DT_SCE_JMPREL               : 'DT_SCE_JMPREL',
            Dynamic.DT_SCE_PLTREL               : 'DT_SCE_PLTREL',
            Dynamic.DT_SCE_PLTRELSZ             : 'DT_SCE_PLTRELSZ',
            Dynamic.DT_SCE_RELA                 : 'DT_SCE_RELA',
            Dynamic.DT_SCE_RELASZ               : 'DT_SCE_RELASZ',
            Dynamic.DT_SCE_RELAENT              : 'DT_SCE_RELAENT',
            Dynamic.DT_SCE_STRTAB               : 'DT_SCE_STRTAB',
            Dynamic.DT_SCE_STRSZ                : 'DT_SCE_STRSZ',
            Dynamic.DT_SCE_SYMTAB               : 'DT_SCE_SYMTAB',
            Dynamic.DT_SCE_SYMENT               : 'DT_SCE_SYMENT',
            Dynamic.DT_SCE_HASHSZ               : 'DT_SCE_HASHSZ',
            Dynamic.DT_SCE_SYMTABSZ             : 'DT_SCE_SYMTABSZ',
            Dynamic.DT_SCE_HIOS                 : 'DT_SCE_HIOS',
            Dynamic.DT_GNU_HASH                 : 'DT_GNU_HASH',
            Dynamic.DT_VERSYM                   : 'DT_VERSYM',
            Dynamic.DT_RELACOUNT                : 'DT_RELACOUNT',
            Dynamic.DT_RELCOUNT                 : 'DT_RELCOUNT',
            Dynamic.DT_FLAGS_1                  : 'DT_FLAGS_1',
            Dynamic.DT_VERDEF                   : 'DT_VERDEF',
            Dynamic.DT_VERDEFNUM                : 'DT_VERDEFNUM',
        }.get(self.TAG, 'Missing Dynamic Tag!!!')
    
    def lib_attribute(self):
    
        return {
            0x1  : 'AUTO_EXPORT',
            0x2  : 'WEAK_EXPORT',
            0x8  : 'LOOSE_IMPORT',
            0x9  : 'AUTO_EXPORT|LOOSE_IMPORT',
            0x10 : 'WEAK_EXPORT|LOOSE_IMPORT',
        }.get(self.INDEX, 'Missing Import Library Attribute!!!')
    
    def mod_attribute(self):
    
        return {
            0x0  : 'NONE',
            0x1  : 'SCE_CANT_STOP',
            0x2  : 'SCE_EXCLUSIVE_LOAD',
            0x4  : 'SCE_EXCLUSIVE_START',
            0x8  : 'SCE_CAN_RESTART',
            0x10 : 'SCE_CAN_RELOCATE',
            0x20 : 'SCE_CANT_SHARE',
        }.get(self.INDEX, 'Missing Module Attribute!!!')
    
    def process(self, dumped, stubs, modules):
    
        if self.TAG == Dynamic.DT_NEEDED:
            stubs[self.VALUE] = 0
        elif self.TAG == Dynamic.DT_PLTGOT:
            self.VALUE += dumped
            Dynamic.PLTGOT = self.VALUE
        elif self.TAG == Dynamic.DT_HASH:
            self.VALUE += dumped
            Dynamic.HASH = self.VALUE
        elif self.TAG == Dynamic.DT_STRTAB:
            self.VALUE += dumped
            Dynamic.STRTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SYMTAB:
            self.VALUE += dumped
            Dynamic.SYMTAB = self.VALUE
        elif self.TAG == Dynamic.DT_STRSZ:
            Dynamic.STRSZ = self.VALUE
        elif self.TAG == Dynamic.DT_INIT:
            self.VALUE += dumped
            Dynamic.INIT = self.VALUE
        elif self.TAG == Dynamic.DT_FINI:
            self.VALUE += dumped
            Dynamic.FINI = self.VALUE
        elif self.TAG == Dynamic.DT_SONAME:
            stubs[self.VALUE] = 0
        elif self.TAG == Dynamic.DT_SCE_STRTAB:
            self.VALUE += dumped
            Dynamic.DYNSTR = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_STRSZ:
            Dynamic.DYNSTRSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_SYMTAB:
            self.VALUE += dumped
            Dynamic.DYNSYM = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_SYMTABSZ:
            Dynamic.DYNSYMSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_JMPREL:
            self.VALUE += dumped
            Dynamic.JMPTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTRELSZ:
            Dynamic.JMPTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTREL:
            if self.VALUE == 0x7:
                return '%s | %#x | DT_RELA' % (self.tag(), self.VALUE)
        elif self.TAG == Dynamic.DT_SCE_RELA:
            self.VALUE += dumped
            Dynamic.RELATAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_RELASZ:
            Dynamic.RELATABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_HASH:
            self.VALUE += dumped
            Dynamic.HASHTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_HASHSZ:
            Dynamic.HASHTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTGOT:
            self.VALUE += dumped
            Dynamic.GOT = self.VALUE
        elif self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_IMPORT_LIB,
                          Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB,
                          Dynamic.DT_SCE_EXPORT_LIB_ATTR, Dynamic.DT_SCE_MODULE_INFO,
                          Dynamic.DT_SCE_MODULE_ATTR, Dynamic.DT_SCE_ORIGINAL_FILENAME]:
            self.ID             = self.VALUE >> 48
            self.VERSION_MINOR  = (self.VALUE >> 40) & 0xF
            self.VERSION_MAJOR  = (self.VALUE >> 32) & 0xF
            self.INDEX          = self.VALUE & 0xFFF
            
            if self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_MODULE_INFO]:
                if self.INDEX not in modules:
                    modules[self.INDEX] = 0
                return '%s | %#x | MID:%#x Version:%i.%i | %#x' % \
                       (self.tag(), self.VALUE, self.ID, self.VERSION_MAJOR, self.VERSION_MINOR, self.INDEX)
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB, Dynamic.DT_SCE_EXPORT_LIB]:
                if self.INDEX not in modules:
                    modules[self.INDEX] = 0
                return '%s | %#x | LID:%#x Version:%i | %#x' % \
                       (self.tag(), self.VALUE, self.ID, self.VERSION_MAJOR, self.INDEX)
            elif self.TAG == Dynamic.DT_SCE_MODULE_ATTR:
                return '%s | %#x | %s' % (self.tag(), self.VALUE, self.mod_attribute())
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB_ATTR]:
                return '%s | %#x | LID:%#x Attributes:%s' % \
                       (self.tag(), self.VALUE, self.ID, self.lib_attribute())
            elif self.TAG == Dynamic.DT_SCE_ORIGINAL_FILENAME:
                stubs[self.INDEX] = 0
        
        return '%s | %#x' % (self.tag(), self.VALUE)
    

class Relocation:

    __slots__ = ('OFFSET', 'INDEX', 'INFO', 'ADDEND', 'RELSTR')
    
    # PS4 (X86_64) Relocation Codes (40)
    (R_X86_64_NONE, R_X86_64_64, R_X86_64_PC32, R_X86_64_GOT32,
    R_X86_64_PLT32, R_X86_64_COPY, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE, R_X86_64_GOTPCREL, R_X86_64_32, R_X86_64_32S,
    R_X86_64_16, R_X86_64_PC16, R_X86_64_8, R_X86_64_PC8, R_X86_64_DTPMOD64,
    R_X86_64_DTPOFF64, R_X86_64_TPOFF64, R_X86_64_TLSGD, R_X86_64_TLSLD,
    R_X86_64_DTPOFF32, R_X86_64_GOTTPOFF, R_X86_64_TPOFF32, R_X86_64_PC64,
    R_X86_64_GOTOFF64, R_X86_64_GOTPC32, R_X86_64_GOT64, R_X86_64_GOTPCREL64,
    R_X86_64_GOTPC64, R_X86_64_GOTPLT64, R_X86_64_PLTOFF64, R_X86_64_SIZE32,
    R_X86_64_SIZE64, R_X86_64_GOTPC32_TLSDESC, R_X86_64_TLSDESC_CALL, R_X86_64_TLSDESC,
    R_X86_64_IRELATIVE, R_X86_64_RELATIVE64) = range(0x27)
    R_X86_64_ORBIS_GOTPCREL_LOAD             = 0x28
    
    def __init__(self, f):
    
        self.OFFSET = struct.unpack('<Q', f.read(8))[0]
        self.INFO   = struct.unpack('<Q', f.read(8))[0]
        self.ADDEND = struct.unpack('<Q', f.read(8))[0]
    
    def ps4(self):
    
        return {
            Relocation.R_X86_64_NONE                : 'R_X86_64_NONE',
            Relocation.R_X86_64_64                  : 'R_X86_64_64',
            Relocation.R_X86_64_PC32                : 'R_X86_64_PC32',
            Relocation.R_X86_64_GOT32               : 'R_X86_64_GOT32',
            Relocation.R_X86_64_PLT32               : 'R_X86_64_PLT32',
            Relocation.R_X86_64_COPY                : 'R_X86_64_COPY',
            Relocation.R_X86_64_GLOB_DAT            : 'R_X86_64_GLOB_DAT',
            Relocation.R_X86_64_JUMP_SLOT           : 'R_X86_64_JUMP_SLOT',
            Relocation.R_X86_64_RELATIVE            : 'R_X86_64_RELATIVE',
            Relocation.R_X86_64_GOTPCREL            : 'R_X86_64_GOTPCREL',
            Relocation.R_X86_64_32                  : 'R_X86_64_32',
            Relocation.R_X86_64_32S                 : 'R_X86_64_32S',
            Relocation.R_X86_64_16                  : 'R_X86_64_16',
            Relocation.R_X86_64_PC16                : 'R_X86_64_PC16',
            Relocation.R_X86_64_8                   : 'R_X86_64_8',
            Relocation.R_X86_64_PC8                 : 'R_X86_64_PC8',
            Relocation.R_X86_64_DTPMOD64            : 'R_X86_64_DTPMOD64',
            Relocation.R_X86_64_DTPOFF64            : 'R_X86_64_DTPOFF64',
            Relocation.R_X86_64_TPOFF64             : 'R_X86_64_TPOFF64',
            Relocation.R_X86_64_TLSGD               : 'R_X86_64_TLSGD',
            Relocation.R_X86_64_TLSLD               : 'R_X86_64_TLSLD',
            Relocation.R_X86_64_DTPOFF32            : 'R_X86_64_DTPOFF32',
            Relocation.R_X86_64_GOTTPOFF            : 'R_X86_64_GOTTPOFF',
            Relocation.R_X86_64_TPOFF32             : 'R_X86_64_TPOFF32',
            Relocation.R_X86_64_PC64                : 'R_X86_64_PC64',
            Relocation.R_X86_64_GOTOFF64            : 'R_X86_64_GOTOFF64',
            Relocation.R_X86_64_GOTPC32             : 'R_X86_64_GOTPC32',
            Relocation.R_X86_64_GOT64               : 'R_X86_64_GOT64',
            Relocation.R_X86_64_GOTPCREL64          : 'R_X86_64_GOTPCREL64',
            Relocation.R_X86_64_GOTPC64             : 'R_X86_64_GOTPC64',
            Relocation.R_X86_64_GOTPLT64            : 'R_X86_64_GOTPLT64',
            Relocation.R_X86_64_PLTOFF64            : 'R_X86_64_PLTOFF64',
            Relocation.R_X86_64_SIZE32              : 'R_X86_64_SIZE32',
            Relocation.R_X86_64_SIZE64              : 'R_X86_64_SIZE64',
            Relocation.R_X86_64_GOTPC32_TLSDESC     : 'R_X86_64_GOTPC32_TLSDESC',
            Relocation.R_X86_64_TLSDESC_CALL        : 'R_X86_64_TLSDESC_CALL',
            Relocation.R_X86_64_TLSDESC             : 'R_X86_64_TLSDESC',
            Relocation.R_X86_64_IRELATIVE           : 'R_X86_64_IRELATIVE',
            Relocation.R_X86_64_RELATIVE64          : 'R_X86_64_RELATIVE64',
            Relocation.R_X86_64_ORBIS_GOTPCREL_LOAD : 'R_X86_64_ORBIS_GOTPCREL_LOAD',
        }.get(self.INFO, 'Missing PS4 Relocation Type!!!')
    
    def process(self, dumped, end):
    
        # String (Offset) == Base + AddEnd (B + A)
        if self.ps4() in ['R_X86_64_RELATIVE']:
            
            if dumped:
                self.OFFSET += dumped
                self.ADDEND += dumped
            
            idaapi.create_data(self.OFFSET, FF_QWORD, 0x8, BADNODE)
            idaapi.put_qword(self.OFFSET, self.ADDEND)
            
            if end < self.ADDEND:
                idaapi.create_data(self.ADDEND, FF_QWORD, 0x8, BADNODE)
            
            return '%#x | %s | %#x' % (self.OFFSET, self.ps4(), self.ADDEND)
    

class Symbol:

    __slots__ = ('NAME', 'INFO', 'OTHER', 'INDEX', 'VALUE', 'SIZE')
    
    # Symbol Information
    ST_LOCAL_NONE      = 0x0
    ST_LOCAL_OBJECT    = 0x1
    ST_LOCAL_FUNCTION  = 0x2
    ST_LOCAL_SECTION   = 0x3
    ST_LOCAL_FILE      = 0x4
    ST_LOCAL_COMMON    = 0x5
    ST_LOCAL_TLS       = 0x6
    ST_GLOBAL_NONE     = 0x10
    ST_GLOBAL_OBJECT   = 0x11
    ST_GLOBAL_FUNCTION = 0x12
    ST_GLOBAL_SECTION  = 0x13
    ST_GLOBAL_FILE     = 0x14
    ST_GLOBAL_COMMON   = 0x15
    ST_GLOBAL_TLS      = 0x16
    ST_WEAK_NONE       = 0x20
    ST_WEAK_OBJECT     = 0x21
    ST_WEAK_FUNCTION   = 0x22
    ST_WEAK_SECTION    = 0x23
    ST_WEAK_FILE       = 0x24
    ST_WEAK_COMMON     = 0x25
    ST_WEAK_TLS        = 0x26
    
    def __init__(self, f):
    
        self.NAME      = struct.unpack('<I', f.read(4))[0]
        self.INFO      = struct.unpack('<B', f.read(1))[0]
        self.OTHER     = struct.unpack('<B', f.read(1))[0]
        self.SHINDEX   = struct.unpack('<H', f.read(2))[0]
        self.VALUE     = struct.unpack('<Q', f.read(8))[0]
        self.SIZE      = struct.unpack('<Q', f.read(8))[0]
    
    def info(self):
    
        return {
            Symbol.ST_LOCAL_NONE      : 'Local : None',
            Symbol.ST_LOCAL_OBJECT    : 'Local : Object',
            Symbol.ST_LOCAL_FUNCTION  : 'Local : Function',
            Symbol.ST_LOCAL_SECTION   : 'Local : Section',
            Symbol.ST_LOCAL_FILE      : 'Local : File',
            Symbol.ST_LOCAL_COMMON    : 'Local : Common',
            Symbol.ST_LOCAL_TLS       : 'Local : TLS',
            Symbol.ST_GLOBAL_NONE     : 'Global : None',
            Symbol.ST_GLOBAL_OBJECT   : 'Global : Object',
            Symbol.ST_GLOBAL_FUNCTION : 'Global : Function',
            Symbol.ST_GLOBAL_SECTION  : 'Global : Section',
            Symbol.ST_GLOBAL_FILE     : 'Global : File',
            Symbol.ST_GLOBAL_COMMON   : 'Global : Common',
            Symbol.ST_GLOBAL_TLS      : 'Global : TLS',
            Symbol.ST_WEAK_NONE       : 'Weak : None',
            Symbol.ST_WEAK_OBJECT     : 'Weak : Object',
            Symbol.ST_WEAK_FUNCTION   : 'Weak : Function',
            Symbol.ST_WEAK_SECTION    : 'Weak : Section',
            Symbol.ST_WEAK_FILE       : 'Weak : File',
            Symbol.ST_WEAK_COMMON     : 'Weak : Common',
            Symbol.ST_WEAK_TLS        : 'Weak : TLS',
        }.get(self.INFO, 'Missing Symbol Information!!!')
    
    def process(self, functions):
    
        if self.NAME != 0:
            functions[self.NAME] = 0
        
        if 'Function' in self.info():
            idaapi.add_func(self.VALUE, BADADDR)
        
        return self.info()
    
    def resolve(self, function):
    
        if 'Function' in self.info() and self.VALUE > 0:
            idc.set_name(self.VALUE, function, SN_NOCHECK | SN_NOWARN | SN_FORCE)
    

# PROGRAM START

# Open File Dialog...
def accept_file(f, n):
    
    # Only support using 64-bit IDA - Will fix this later...
    
    #if cvar.inf.is_64bit() and f.size() > 0x40:
    if f.size() > 0x40:
        ps4 = Binary(f)
    
    # Non-Symbol Kernels
    if ps4.E_START_ADDR > 0xFFFFFFFF82200000 and ps4.E_SEGMENTS[0].FILE_SIZE != 0x118:
        return { 'format'  : 'PS4 - Kernel',
                 'options' : ACCEPT_FIRST }
    
    return 0

# Since IDA cannot create a compatibility layer to save its life...
def find_binary(address, end, search, format, flags):
    
    # Is this really so hard Ilfak?
    # Not only do you break it between the beta and the release candidate... 
    # You then have the audacity to write in your release notes that you added find_binary, but it is nowhere to be seen
    # Feel free to take this version and modify it though to fit all edge cases, and in the spirit of your latest release, for free!
    if idaapi.IDA_SDK_VERSION > 760:
        binpat = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binpat, address, search, format)
        
        # 9.0 RC1
        try:
            address, _ = idaapi.bin_search(address, end, binpat, flags)
        # 9.0 Beta
        except:
            address, _ = idaapi.bin_search3(address, end, binpat, flags)
    else:
        address = idaapi.find_binary(address, end, search, format, flags)
    
    return address

# Chendo's cdevsw con-struct-or
def chendo(address, end, search, struct):
    
    while address < end:
        address = find_binary(address, end, search, 0x10, SEARCH_DOWN)
        idaapi.del_items(address, 0xB0, 0)
        idaapi.create_struct(address, 0xB0, struct)
        address += 0x8

# Kiwidog's __stack_chk_fail
def kiwidog(address, end, search):
    
    magic = find_binary(address, end, search, 0x0, SEARCH_DOWN)
    function = idaapi.get_func(idaapi.get_first_dref_to(magic))
    idaapi.set_name(function.start_ea, '__stack_chk_fail', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    function.flags |= FUNC_NORET
    idaapi.update_func(function)

# Pablo's IDC
def pablo(mode, address, end, search):
    
    while address < end:
        address = find_binary(address, end, search, 0x10, SEARCH_DOWN)
        
        if address > idaapi.get_segm_by_name('CODE').end_ea:
            offset = address - 0x3
            
            if idaapi.is_unknown(idaapi.getFlags(offset)):
                if idaapi.get_qword(offset) <= end:
                    idaapi.create_data(offset, FF_QWORD, 0x8, BADNODE)
            
            address = offset + 4
        
        else:
            address += mode
            idaapi.del_items(address, 0)
            idaapi.create_insn(address)
            idaapi.add_func(address, BADADDR)
            address += 1

# Znullptr's Syscalls
def znullptr(address, end, search, struct):
    
    magic = find_binary(address, end, search, 0x10, SEARCH_DOWN)
    pattern = '%02X %02X %02X %02X FF FF FF FF' % (magic & 0xFF, ((magic >> 0x8) & 0xFF), ((magic >> 0x10) & 0xFF), ((magic >> 0x18) & 0xFF))
    
    sysvec = find_binary(end, 0xFFFFFFFFFFFFFFFF, pattern, 0x10, SEARCH_UP) - 0x60 #cvar.inf.max_ea
    idaapi.set_name(sysvec, 'sysentvec', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    sysent = idaapi.get_qword(sysvec + 0x8)
    idaapi.set_name(sysent, 'sv_table', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    sysnames = idaapi.get_qword(sysvec + 0xD0)
    idaapi.set_name(sysnames, 'sv_syscallnames', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # Get the list of syscalls
    offset = find_binary(address, 0xFFFFFFFFFFFFFFFF, '73 79 73 63 61 6C 6C 00 65 78 69 74 00', 0x10, SEARCH_DOWN) #cvar.inf.max_ea
    
    numsyscalls = idaapi.get_qword(sysvec)
    for entry in range(numsyscalls):
        initial = sysnames + (entry * 0x8)
        idc.create_data(initial, FF_QWORD, 0x8, BADNODE)
        offset = idaapi.get_qword(initial)
        
        length = idaapi.get_max_strlit_length(offset, STRTYPE_C)
        name = idaapi.get_strlit_contents(offset, length, STRTYPE_C).decode()
        
        # Skip
        if 'obs_{' in name:
            name = '%i' % entry
        elif '#' in name:
            name = name.split('#')[1]
        elif '.' in name:
            name = name.split('.')[1]
        
        sysentoffset = sysent + 0x8 + (entry * 0x30)
        idaapi.del_items(sysentoffset - 0x8, 0x30, 0)
        idaapi.create_struct(sysentoffset - 0x8, 0x30, struct)
        idc.set_cmt(sysentoffset - 0x8, '#%i' % entry, False)
        
        # Rename the functions
        function = idaapi.get_qword(sysentoffset)
        name = 'sys_' + name
        
        # Compatibility ? Unsure why we have to encode the string for python 2...
        if idaapi.IDA_SDK_VERSION < 750:
            name = name.encode()
        
        idaapi.set_name(function, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        idc.apply_type(function, idc.parse_decl('__int64 sys_%s(struct thread* td, struct default_uap* uap);' % name, 0), TINFO_DEFINITE)

# Load Input Binary...
def load_file(f, neflags, format):

    print('# PS4 Kernel Loader')
    ps4 = Binary(f)
    
    # PS4 Processor, Compiler, Library
    bitness = ps4.procomp('metapc', CM_N64 | CM_M_NN | CM_CC_FASTCALL, 'gnulnx_x64')
    
    # Segment Loading...
    for segm in ps4.E_SEGMENTS:
        
        # Process Loadable Segments...
        if segm.name() in ['CODE', 'DATA', 'SCE_RELRO']:
            address = segm.MEM_ADDR
            size = segm.MEM_SIZE
            
            # Dumped Kernel Fix-ups
            if segm.name() in ['DATA', 'SCE_RELRO'] and idaapi.get_segm_by_name('CODE').start_ea != 0xFFFFFFFF82200000:
                offset = address - idaapi.get_segm_by_name('CODE').start_ea
                dumped = segm.MEM_SIZE
            else:
                offset = segm.OFFSET
                dumped = segm.FILE_SIZE
            
            print('# Creating %s Segment...' % segm.name())
            f.file2base(offset, address, address + dumped, FILEREG_PATCHABLE)
            
            idaapi.add_segm(0, address, address + size, segm.name(), segm.type(), ADDSEG_NOTRUNC | ADDSEG_FILLGAP)
            
            # Processor Specific Segment Details
            idc.set_segm_addressing(address, bitness)
            idc.set_segm_alignment(address, segm.alignment())
            idc.set_segm_attr(address, SEGATTR_PERM, segm.flags())
        
        # Process Dynamic Segment...
        elif segm.name() == 'DYNAMIC':
            code = idaapi.get_segm_by_name('CODE')
            data = idaapi.get_segm_by_name('DATA')
            relro = idaapi.get_segm_by_name('SCE_RELRO')
            
            # ------------------------------------------------------------------------------------------------------------
            # Dynamic Tag Entry Structure
            members = [('tag', 'Tag', 0x8),
                       ('value', 'Value', 0x8)]
            struct = segm.struct('Tag', members)
            
            # Dynamic Tag Table
            stubs = {}
            modules = {}
            location = segm.MEM_ADDR
            
            # Dumps are offset by a small amount
            if code.start_ea != 0xFFFFFFFF82200000:
                dumped = code.start_ea - 0xFFFFFFFF82200000
            else:
                dumped = 0
            
            f.seek(location - code.start_ea)
            for entry in range(int(segm.MEM_SIZE / 0x10)):
                idaapi.create_struct(location + (entry * 0x10), 0x10, struct)
                idc.set_cmt(location + (entry * 0x10), Dynamic(f).process(dumped, stubs, modules), False)
            
            # ------------------------------------------------------------------------------------------------------------
            # Hash Entry Structure
            members = [('bucket', 'Bucket', 0x2),
                       ('chain', 'Chain', 0x2),
                       ('buckets', 'Buckets', 0x2),
                       ('chains', 'Chains', 0x2)]
            struct = segm.struct('Hash', members)
            
            # Hash Table
            try:
                location = Dynamic.HASHTAB
                size = Dynamic.HASHTABSZ
            
            except:
                location = Dynamic.HASH
                size = Dynamic.SYMTAB - location
            
            f.seek(location - code.start_ea)
            for entry in range(int(size / 0x8)):
                idaapi.create_struct(location + (entry * 0x8), 0x8, struct)
            
            # --------------------------------------------------------------------------------------------------------
            # Relocation Entry Structure (with specific addends)
            members = [('offset', 'Offset (String Index)', 0x8),
                       ('info', 'Info (Symbol Index : Relocation Code)', 0x8),
                       ('addend', 'AddEnd', 0x8)]
            struct = segm.struct('Relocation', members)
            
            # Relocation Table (with specific addends)
            location = Dynamic.RELATAB
            
            f.seek(location - code.start_ea)
            for entry in range(int(Dynamic.RELATABSZ / 0x18)):
                idaapi.create_struct(location + (entry * 0x18), 0x18, struct)
                idc.set_cmt(location + (entry * 0x18), Relocation(f).process(dumped, code.end_ea), False)
            
            # Initialization Function
            idc.add_entry(Dynamic.INIT, Dynamic.INIT, '.init', True)
    
    address = code.start_ea
    
    # ELF Header Structure
    members = [('File format', 0x4),
               ('File class', 0x1),
               ('Data encoding', 0x1),
               ('File version', 0x1),
               ('OS/ABI', 0x1),
               ('ABI version', 0x1),
               ('Padding', 0x7),
               ('File type', 0x2),
               ('Machine', 0x2),
               ('File version', 0x4),
               ('Entry point', 0x8),
               ('PHT file offset', 0x8),
               ('SHT file offset', 0x8),
               ('Processor-specific flags', 0x4),
               ('ELF header size', 0x2),
               ('PHT entry size', 0x2),
               ('Number of entries in PHT', 0x2),
               ('SHT entry size', 0x2),
               ('Number of entries in SHT', 0x2),
               ('SHT entry index for string table\n', 0x2)]
    
    for (comment, size) in members:
        flags = idaapi.get_flags_by_size(size)
        idc.create_data(address, flags if flags != 0 else FF_STRLIT, size, BADNODE)
        idc.set_cmt(address, comment, False)
        address += size
    
    for index, entry in enumerate(ps4.E_SEGMENTS):
        # ELF Program Header Structure
        members = [('Type: %s' % entry.name(), 0x4),
                   ('Flags', 0x4),
                   ('File offset', 0x8),
                   ('Virtual address', 0x8),
                   ('Physical address', 0x8),
                   ('Size in file image', 0x8),
                   ('Size in memory image', 0x8),
                   ('Alignment\n', 0x8)]
        
        for (comment, size) in members:
            flags = idaapi.get_flags_by_size(size)
            
            idc.create_data(address, flags if flags != 0 else FF_STRLIT, size, BADNODE)
            idc.set_cmt(address, comment, False)
            address += size
    
    # Start Function
    idc.add_entry(ps4.E_START_ADDR, ps4.E_START_ADDR, 'start', True)
    
    # Xfast_syscall
    address = find_binary(code.start_ea, code.end_ea, '0F 01 F8 65 48 89 24 25 A8 02 00 00 65 48 8B 24', 0x10, SEARCH_DOWN)
    idaapi.del_items(address, 0)
    idaapi.create_insn(address)
    idaapi.add_func(address, BADADDR)
    idaapi.set_name(address, 'Xfast_syscall', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # Znullptr's syscalls
    print('# Processing Znullptr\'s Syscalls...')
    
    # Syscall Entry Structure
    members = [('narg', 'Number of Arguments', 0x4),
               ('_pad', 'Padding', 0x4),
               ('function', 'Function', 0x8),
               ('auevent', 'Augmented Event?', 0x2),
               ('_pad1', 'Padding', 0x2),
               ('_pad2', 'Padding', 0x4),
               ('trace_args_func', 'Trace Arguments Function', 0x8),
               ('entry', 'Entry', 0x4),
               ('return', 'Return', 0x4),
               ('flags', 'Flags', 0x4),
               ('thrcnt', 'Thread Count?', 0x4)]
    struct = segm.struct('Syscall', members)
    
    znullptr(code.start_ea, code.end_ea, '4F 52 42 49 53 20 6B 65 72 6E 65 6C 20 53 45 4C 46', struct)
    
    # --------------------------------------------------------------------------------------------------------
    # Chendo's cdevsw con-struct-or
    print('# Processing Chendo\'s Structures...')
    
    # cdevsw Entry Structure
    members = [('d_version', 'Version', 0x4),
               ('d_flags', 'Flags', 0x4),
               ('d_name', 'Name', 0x8),
               ('d_open', 'Open', 0x8),
               ('d_fdopen', 'File Descriptor Open', 0x8),
               ('d_close', 'Close', 0x8),
               ('d_read', 'Read', 0x8),
               ('d_write', 'Write', 0x8),
               ('d_ioctl', 'Input/Ouput Control', 0x8),
               ('d_poll', 'Poll', 0x8),
               ('d_mmap', 'Memory Mapping', 0x8),
               ('d_strategy', 'Strategy', 0x8),
               ('d_dump', 'Dump', 0x8),
               ('d_kqfilter', 'KQFilter', 0x8),
               ('d_purge', 'Purge', 0x8),
               ('d_mmap_single', 'Single Memory Mapping', 0x8),
               ('d_spare0', 'Spare0', 0x8),
               ('d_spare1', 'Spare1', 0x8),
               ('d_spare2', 'Spare2', 0x8),
               ('d_spare3', 'Spare3', 0x8),
               ('d_spare4', 'Spare4', 0x8),
               ('d_spare5', 'Spare5', 0x8),
               ('d_spare6', 'Spare6', 0x4),
               ('d_spare7', 'Spare7', 0x4)]
    struct = segm.struct('cdevsw', members)
    
    chendo(data.start_ea, data.end_ea, '09 20 12 17', struct)
    
    # --------------------------------------------------------------------------------------------------------
    # Pablo's IDC
    try:
        print('# Processing Pablo\'s Push IDC...')
        
        # Script 1) Push it real good...
        # Default patterns set
        pablo(0, code.start_ea, 0x10, '55 48 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'C3 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '66 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'C9 C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '0F 0B 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'EB ?? 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '5D C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '5B C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 41 ?? 41 ??')
        pablo(2, code.start_ea, code.end_ea, '66 90 48 81 EC ?? 00 00 00')
        pablo(2, code.start_ea, code.end_ea, '0F 0B 48 89 9D ?? ?? FF FF 49 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 53 4C 8B 54 24 20')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 41 56 53')
        pablo(2, code.start_ea, code.end_ea, '90 90 53 48 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 41 ?? 41 ??')
        pablo(3, code.start_ea, code.end_ea, '0F 0B 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, 'EB ?? 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5F C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5C C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '31 C0 C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5D C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5E C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '66 66 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '0F 1F 00 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 ?? C3 53 48')
        pablo(3, code.start_ea, code.end_ea, '0F 1F 00 48 81 EC ?? 00 00 00')
        pablo(4, code.start_ea, code.end_ea, '0F 1F 40 00 55 48 ??')
        pablo(4, code.start_ea, code.end_ea, '0F 1F 40 00 48 81 EC ?? 00 00 00')
        pablo(5, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '48 83 C4 ?? C3 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '0F 1F 44 00 00 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '0F 1F 44 00 00 48 81 EC ?? 00 00 00')
        pablo(6, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 55 48 ??')
        pablo(6, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 90 55 48 ??')
        pablo(6, code.start_ea, code.end_ea, '66 0F 1F 44 00 00 55 48 ??')
        pablo(7, code.start_ea, code.end_ea, '0F 1F 80 00 00 00 00 55 48 ??')
        pablo(8, code.start_ea, code.end_ea, '0F 1F 84 00 00 00 00 00 55 48 ??')
        pablo(8, code.start_ea, code.end_ea, 'C3 0F 1F 80 00 00 00 00 48')
        pablo(8, code.start_ea, code.end_ea, '0F 1F 84 00 00 00 00 00 53 48 83 EC')
        
        # Special cases patterns set
        pablo(13, code.start_ea, code.end_ea, 'C3 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(13, code.start_ea, code.end_ea, 'C3 90 90 90 90 90 90 90 90 90 90 90 90 55')
        pablo(17, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(19, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(19, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(20, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(20, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        
        # Script 2) Fix-up Dumped Data Pointers...
        if dumped:
            print('# Processing Pablo\'s Dumped Data Pointers IDC...')
            pablo(0, data.start_ea, data.end_ea, '?? FF FF FF FF')
        
    except:
        pass
    
    # --------------------------------------------------------------------------------------------------------
    # Kiwidog's __stack_chk_fail
    print('# Processing Kiwidog\'s Stack Functions...')
    
    kiwidog(code.start_ea, code.end_ea, '73 74 61 63 6B 20 6F 76 65 72 66 6C 6F 77 20 64 65 74 65 63 74 65 64 3B')
    
    print('# Done!')
    return 1

# PROGRAM END
