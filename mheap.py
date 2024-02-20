from cgitb import small
from distutils.log import debug
from struct import Struct
from termios import CSIZE
import lldb,os
from ctypes import *
from libnum import *

LARGE_ENTRY_CACHE_SIZE = 16
PAGE_MAX_SHIFT = 14     # 14?
PAGE_MAX_SIZE = 1<<PAGE_MAX_SHIFT
CACHE_LINE = 32
TINY_MAX_MAGAZINES = 32
TINY_CACHE = True

SHIFT_TINY_QUANTUM = 4
SHIFT_SMALL_QUANTUM = SHIFT_TINY_QUANTUM+5

INITIAL_NUM_REGIONS_SHIFT = 6
INITIAL_NUM_REGIONS = (1 << INITIAL_NUM_REGIONS_SHIFT)

NYBBLE = 4
ANTI_NYBBLE = 64 - NYBBLE

class bcolors:
    HEADER = '\033[33m'
    INFO = '\033[36m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class myStructure(Structure):
    def _format_value(self, value, dtype):
        if isinstance(value, Array):
            # Use Array undocumented _type_:
            text = ', '.join([ self._format_value(x, value._type_) for x in value ])
            return f'[{text}]'
        elif type(value) == int:
            size = sizeof(dtype) * 2   # size mutliply by byte width
            return f'0x{value:0{size}x}'
        else:
            return f'{value}'
    
    def _format_field(self, field):
        name, dtype, *bitsize = field
        value = getattr(self, name)
        return f'\t{name} = {self._format_value(value, dtype)}'

    def __repr__(self):
        text = ';\n'.join( [ self._format_field(x) for x in self._fields_ ] )
        return f'<{self.__class__.__name__}={text}>'
    def __getitem__(self, i):
        if type(i)==str: return getattr(self, i)
        return getattr(self, self._fields_[i][0])
    def __len__(self):
        return len(self._fields_)

class malloc_zone_t(myStructure):
    _fields_ = [('reserved1', c_uint64),
                ('reserved2', c_uint64),
                ('size', c_uint64),
                ('malloc', c_uint64),
                ('calloc', c_uint64),
                ('valloc', c_uint64),
                ('free', c_uint64),
                ('realloc', c_uint64),
                ('destroy', c_uint64),
                ('zone_name', c_char_p),
                ('batch_malloc', c_uint64),
                ('batch_free', c_uint64),
                ('MALLOC_INTROSPECT_TBL_PTR', c_uint64),
                ('version', c_uint),
                ('memalign', c_uint64),
                ('free_definite_size', c_uint64),
                ('pressure_relief', c_uint64),
                ('claimed_address', c_uint64),]

class _malloc_lock_s(myStructure):
    _fields_ = [
        ('osl_type', c_uint64),
        ('_osl_handoff_opaque', c_uint64),
    ]

class region_hash_generation_t(myStructure):
    _fields_ = [('num_regions_allocated', c_size_t),
                ('num_regions_allocated_shift', c_size_t),
                ('hashed_regions', c_uint64),
                ('nextgen', c_uint64)]

class tiny_free_list_t(myStructure):
    _fields_ = [('previous', c_uint64),
                ('next', c_uint64)]
    
    def get_prev(self):
        return (self.previous & 0xfffffffffffffff) << 4

    def get_next(self):
        return (self.next & 0xfffffffffffffff) << 4

class small_free_list_t(myStructure):
    _fields_ = [('previous', c_uint64),
                ('prev_checksum', c_uint64),
                ('next', c_uint64),
                ('next_checksum', c_uint64)]
    
    def get_prev(self):
        return self.previous

    def get_next(self):
        return self.next

class oob_free_entry_s(myStructure):
    _fields_ = [('previous', c_uint64),
                ('next', c_uint64),
                ('ptr', c_uint64)]
    
    def get_prev(self):
        return self.previous

    def get_next(self):
        return self.next

    def is_next_oob_free(self):
        return self.ptr & 0x8000000000000000


class magazine_t(myStructure):
    _fields_ = [
                # ('magazine_lock', _malloc_lock_s),
                ('alloc_underway', c_uint32),
                ('mag_last_free', c_uint64),
                ('mag_last_free_msize', c_size_t),
                ('mag_last_free_rgn', c_uint64),
                ('mag_free_list', c_uint64 * 256),
                ('mag_bitmap', c_uint32 * 8),
                ('reserved_1', c_uint64 * 2),
                ('mag_bytes_free_at_end', c_size_t),
                ('mag_bytes_free_at_start', c_size_t),
                ('mag_last_region', c_uint64),
                ('mag_num_bytes_in_objects', c_size_t),
                ('num_bytes_in_magazine', c_size_t),
                ('mag_num_objects', c_uint),
                ('recirculation_entries', c_uint),
                ('firstNode', c_uint64),
                ('lastNode', c_uint64),
                ('pad', c_uint64 * (320 - 14 - 256 - (8 + 1) // 2))
                ]

    def print_tiny_free_list(self):
        for i in range(0x3f):
            if self.mag_free_list[i]:
                print('[' + hex(i) + '](' + hex((i + 1) * 0x10) + '): ' + hex(self.mag_free_list[i]), end='')
                mem = lldb.process.ReadMemory(self.mag_free_list[i], sizeof(tiny_free_list_t), lldb.SBError())
                chunk = tiny_free_list_t.from_buffer_copy(mem)
                next = chunk.get_next()
                while next:
                    mem = lldb.process.ReadMemory(next, sizeof(tiny_free_list_t), lldb.SBError())
                    if mem:
                        chunk = tiny_free_list_t.from_buffer_copy(mem)
                        print(' -> ' + hex(next), end='')
                        next = chunk.get_next()
                    else:
                        print(' -> ' + bcolors.FAIL + bcolors.BOLD + hex(next) + bcolors.ENDC, end='')
                        print(bcolors.FAIL + bcolors.BOLD + '\nInvalid Address!!!' + bcolors.ENDC)
                        break
                print('')

        # free list 0x3f
        if self.mag_free_list[0x3f]:
                mem = lldb.process.ReadMemory(self.mag_free_list[0x3f], sizeof(tiny_free_list_t) + 0x8, lldb.SBError())
                size = s2n(mem[0x10:0x12][::-1]) * 0x10
                print('[0x3f]: ' + hex(self.mag_free_list[0x3f]) + '(' + hex(size) + ')', end='')
                chunk = tiny_free_list_t.from_buffer_copy(mem)
                next = chunk.get_next()
                while next:
                    mem = lldb.process.ReadMemory(next, sizeof(tiny_free_list_t) + 0x8, lldb.SBError())
                    if mem:
                        size = s2n(mem[0x10:0x12][::-1]) * 0x10
                        print(' -> ' + hex(next) + '(' + hex(size) + ')', end='')
                        chunk = tiny_free_list_t.from_buffer_copy(mem)
                        next = chunk.get_next()
                    else:
                        print(' -> ' + bcolors.FAIL + bcolors.BOLD + hex(next) + bcolors.ENDC, end='')
                        print(bcolors.FAIL + bcolors.BOLD + '\nInvalid Address!!!' + bcolors.ENDC)
                        break
                print('')
        return

# TODO
    def print_small_free_list(self):
        for i in range(256):
            if self.mag_free_list[i]:
                mem = lldb.process.ReadMemory(self.mag_free_list[i], sizeof(small_free_list_t), lldb.SBError())
                if mem[0x17] & 0x80:
                    chunk = oob_free_entry_s.from_buffer_copy(mem)
                    next = chunk.get_next()
                    mem = lldb.process.ReadMemory(next, sizeof(oob_free_entry_s), lldb.SBError())
                    if mem:
                        print('[' + hex(i) + '](oob free chunk): ' + hex(next), end='')
                        chunk = oob_free_entry_s.from_buffer_copy(mem)
                        while chunk.is_next_oob_free():
                            next = chunk.get_next()
                            mem = lldb.process.ReadMemory(next, sizeof(oob_free_entry_s), lldb.SBError())
                            if mem:
                                chunk = oob_free_entry_s.from_buffer_copy(mem)
                                print(' -> ' + hex(next), end='')
                                next = chunk.get_next()
                            else:
                                print(' -> ' + bcolors.FAIL + bcolors.BOLD + hex(next) + bcolors.ENDC, end='')
                                print(bcolors.FAIL + bcolors.BOLD + '\nInvalid Address!!!' + bcolors.ENDC)
                                break

                else:
                    if self.mag_free_list[i] & 0xff:
                        continue
                    print('[' + hex(i) + '](' + hex((i + 1) * 0x200) + '): ' + hex(self.mag_free_list[i]), end='')
                    chunk = small_free_list_t.from_buffer_copy(mem)
                    next = chunk.get_next()
                    while next:
                        mem = lldb.process.ReadMemory(next, sizeof(small_free_list_t), lldb.SBError())
                        if mem:
                            chunk = small_free_list_t.from_buffer_copy(mem)
                            print(' -> ' + hex(next), end='')
                            next = chunk.get_next()
                        else:
                            print(' -> ' + bcolors.FAIL + bcolors.BOLD + hex(next) + bcolors.ENDC, end='')
                            print(bcolors.FAIL + bcolors.BOLD + '\nInvalid Address!!!' + bcolors.ENDC)
                            break
                    print('')

        # # free list 0x3f
        # if self.mag_free_list[0x3f]:
        #         mem = lldb.process.ReadMemory(self.mag_free_list[0x3f], sizeof(tiny_free_list_t) + 0x8, lldb.SBError())
        #         size = s2n(mem[0x10:0x12][::-1]) * 0x10
        #         print('[' + hex(0x3f) + ']: ' + hex(self.mag_free_list[0x3f]) + '(' + hex(size) + ')', end='')
        #         chunk = tiny_free_list_t.from_buffer_copy(mem)
        #         next = chunk.get_next()
        #         while next:
        #             mem = lldb.process.ReadMemory(next, sizeof(tiny_free_list_t) + 0x8, lldb.SBError())
        #             if mem:
        #                 size = s2n(mem[0x10:0x12][::-1]) * 0x10
        #                 print(' -> ' + hex(next) + '(' + hex(size) + ')', end='')
        #                 chunk = tiny_free_list_t.from_buffer_copy(mem)
        #                 next = chunk.get_next()
        #             else:
        #                 print(' -> ' + bcolors.FAIL + bcolors.BOLD + hex(next) + bcolors.ENDC, end='')
        #                 print(bcolors.FAIL + bcolors.BOLD + '\nInvalid Address!!!' + bcolors.ENDC)
        #                 break
        #         print('')
        # return 

class rack_s(myStructure):
    _fields_ = [('region_lock', _malloc_lock_s),
                ('rack_type_t', c_uint),
                ('num_regions', c_size_t),
                ('num_regions_dealloc', c_size_t),
                ('region_generation', c_uint64),
                ('rg', region_hash_generation_t * 2),
                ('initial_regions', c_uint64 * INITIAL_NUM_REGIONS),
                ('num_magazines', c_int),
                ('num_magazines_mask', c_uint),
                ('num_magazines_mask_shift', c_int),
                ('debug_flags', c_uint32),
                ('magazine_t', c_uint64),
                ('cookie', c_uint64),
                ('last_madvise', c_uint64)
                ]

class malloc_zones(myStructure):
    _fields_ = [("z0", c_uint64),
                ("z1", c_uint64)]

class szone_s(myStructure):
    _fields_ = [('basic_zone', malloc_zone_t),
                ('pad', c_uint8 * (PAGE_MAX_SIZE - sizeof(malloc_zone_t))),
                ('cpu_id_key', c_uint64),
                ('debug_flags', c_uint),
                ('log_address', c_uint64),
                ('reserved_1', c_uint8 * 0x58),
                ('tiny_rack', rack_s),
                ('reserved_2', c_uint8 * 0x68),
                ('small_rack', rack_s)]

def flush_mags():
    global tiny_mag, small_mag, z1
    tiny_mag = []
    for i in range(z1.tiny_rack.num_magazines):
        mem = lldb.process.ReadMemory(z1.tiny_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
        tiny_mag.append(magazine_t.from_buffer_copy(mem))
    small_mag = []
    for i in range(z1.tiny_rack.num_magazines):
        mem = lldb.process.ReadMemory(z1.small_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
        small_mag.append(magazine_t.from_buffer_copy(mem))

def last_frees():
    global tiny_mag, z1
    flush_mags()
    for i in range(z1.tiny_rack.num_magazines):
        print('mag[' + hex(i) + ']: ' + hex(tiny_mag[i].mag_last_free))

def tiny_free_list(i):
    global tiny_mag, z1
    # flush_mags()
    tiny_mag[i].print_tiny_free_list()

def tiny_bins():
    global tiny_mag, z1
    flush_mags()
    for i in range(z1.tiny_rack.num_magazines):
        print(bcolors.HEADER + '|---------------- tiny mag[' + hex(i) + '] ----------------|' + bcolors.ENDC)
        print(bcolors.INFO + '[*] last_free: ' + bcolors.ENDC + hex(tiny_mag[i].mag_last_free) + '(' + hex(tiny_mag[i].mag_last_free_msize * 0x10) + ')')
        print(bcolors.INFO + '[*] free_list: ' + bcolors.ENDC)
        tiny_free_list(i)
        print('')

def tinybins(debugger, command, result, internal_dict):
    global tiny_mag, z1
    lldb.target = debugger.GetSelectedTarget()
    lldb.process = lldb.target.GetProcess()
    if not lldb.process.__get_is_alive__():
        print(bcolors.WARNING + 'No process alive.' + bcolors.ENDC)
        return
    if lldb.process.__get_is_running__():
        print(bcolors.WARNING + 'Stop the process first.' + bcolors.ENDC)
        return
    s_malloc_zones = next(m.FindSymbol('malloc_zones') for m in lldb.target.get_modules_array() if m.FindSymbol('malloc_zones').name)
    mem = lldb.process.ReadMemory(int(s_malloc_zones.addr), sizeof(c_uint64), lldb.SBError())
    p_malloc_zones = c_uint64.from_buffer_copy(mem)
    # print('malloc_zones at: ' + hex(p_malloc_zones.value))
    mem = lldb.process.ReadMemory(p_malloc_zones.value, sizeof(malloc_zones), lldb.SBError())
    zones = malloc_zones.from_buffer_copy(mem)
    mem = lldb.process.ReadMemory(zones.z0, sizeof(szone_s), lldb.SBError())
    z0 = szone_s.from_buffer_copy(mem)
    mem = lldb.process.ReadMemory(zones.z1, sizeof(szone_s), lldb.SBError())
    z1 = szone_s.from_buffer_copy(mem)
    tiny_mag = []
    for i in range(z1.tiny_rack.num_magazines):
        mem = lldb.process.ReadMemory(z1.tiny_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
        tiny_mag.append(magazine_t.from_buffer_copy(mem))
    # small_mag = []
    # for i in range(z1.small_rack.num_magazines):
    #     mem = lldb.process.ReadMemory(z1.small_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
    #     small_mag.append(magazine_t.from_buffer_copy(mem))
    tiny_bins()

def small_free_list(i):
    global small_mag, z1
    small_mag[i].print_small_free_list()

def small_bins():
    global small_mag, z1
    flush_mags()
    for i in range(z1.tiny_rack.num_magazines):
        print(bcolors.HEADER + '|---------------- small mag[' + hex(i) + '] ----------------|' + bcolors.ENDC)
        print(bcolors.INFO + '[*] last_free: ' + bcolors.ENDC + hex(small_mag[i].mag_last_free) + '(' + hex(small_mag[i].mag_last_free_msize * 0x200) + ')')
        print(bcolors.INFO + '[*] free_list: ' + bcolors.ENDC)
        small_free_list(i)

def smallbins(debugger, command, result, internal_dict):
    global tiny_mag, z1
    lldb.target = debugger.GetSelectedTarget()
    lldb.process = lldb.target.GetProcess()
    if not lldb.process.__get_is_alive__():
        print(bcolors.WARNING + 'No process alive.' + bcolors.ENDC)
        return
    if lldb.process.__get_is_running__():
        print(bcolors.WARNING + 'Stop the process first.' + bcolors.ENDC)
        return
    s_malloc_zones = next(m.FindSymbol('malloc_zones') for m in lldb.target.get_modules_array() if m.FindSymbol('malloc_zones').name)
    mem = lldb.process.ReadMemory(int(s_malloc_zones.addr), sizeof(c_uint64), lldb.SBError())
    p_malloc_zones = c_uint64.from_buffer_copy(mem)
    # print('malloc_zones at: ' + hex(p_malloc_zones.value))
    mem = lldb.process.ReadMemory(p_malloc_zones.value, sizeof(malloc_zones), lldb.SBError())
    zones = malloc_zones.from_buffer_copy(mem)
    mem = lldb.process.ReadMemory(zones.z0, sizeof(szone_s), lldb.SBError())
    z0 = szone_s.from_buffer_copy(mem)
    mem = lldb.process.ReadMemory(zones.z1, sizeof(szone_s), lldb.SBError())
    z1 = szone_s.from_buffer_copy(mem)
    # tiny_mag = []
    # for i in range(z1.tiny_rack.num_magazines):
    #     mem = lldb.process.ReadMemory(z1.tiny_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
    #     tiny_mag.append(magazine_t.from_buffer_copy(mem))
    small_mag = []
    for i in range(z1.small_rack.num_magazines):
        mem = lldb.process.ReadMemory(z1.small_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
        small_mag.append(magazine_t.from_buffer_copy(mem))
    small_bins()

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f mheap.tinybins tinybins')
    debugger.HandleCommand('command script add -f mheap.smallbins smallbins')
    print('mHeap: "tinybins", "smallbins" commands have been installed.')

# s_malloc_zones, = (m.FindSymbol('malloc_zones') for m in lldb.target.get_modules_array() if m.FindSymbol('malloc_zones').name)

# mem = lldb.process.ReadMemory(int(s_malloc_zones.addr), sizeof(c_uint64), lldb.SBError())
# p_malloc_zones = c_uint64.from_buffer_copy(mem)
# print('malloc_zones at: ' + hex(p_malloc_zones.value))
# mem = lldb.process.ReadMemory(p_malloc_zones.value, sizeof(malloc_zones), lldb.SBError())
# zones = malloc_zones.from_buffer_copy(mem)
# mem = lldb.process.ReadMemory(zones.z0, sizeof(szone_s), lldb.SBError())
# z0 = szone_s.from_buffer_copy(mem)
# mem = lldb.process.ReadMemory(zones.z1, sizeof(szone_s), lldb.SBError())
# z1 = szone_s.from_buffer_copy(mem)
# tiny_mag = []
# for i in range(z1.tiny_rack.num_magazines):
#     mem = lldb.process.ReadMemory(z1.tiny_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
#     tiny_mag.append(magazine_t.from_buffer_copy(mem))
# small_mag = []
# for i in range(z1.small_rack.num_magazines):
#     mem = lldb.process.ReadMemory(z1.small_rack.magazine_t + i * sizeof(magazine_t), sizeof(magazine_t), lldb.SBError())
#     small_mag.append(magazine_t.from_buffer_copy(mem))