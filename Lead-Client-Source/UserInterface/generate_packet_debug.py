#!/usr/bin/env python3
"""
Packet Debug Registration Generator

Parses packet.h and generates PacketDebugRegGen.h with:
- Auto-generated printer functions for each packet struct
- All packet registrations (CG and GC)
- Comments explaining why some packets use hex dump

Usage:
    python generate_packet_debug.py

This will read Lead-Shared-Source/packet.h and generate PacketDebugRegGen.h
"""

import re
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PACKET_H_PATH = os.path.join(SCRIPT_DIR, "..", "..", "Lead-Shared-Source", "packet.h")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "PacketDebugRegGen.h")

# Map C types to printf format specifiers
TYPE_FORMAT = {
    'BYTE': ('u', '%u'),
    'WORD': ('u', '%u'),
    'DWORD': ('u', '%u'),
    'UINT': ('u', '%u'),
    'INT': ('d', '%d'),
    'int': ('d', '%d'),
    'long': ('ld', '%ld'),
    'unsigned long': ('lu', '%lu'),
    'short': ('d', '%d'),
    'unsigned short': ('u', '%u'),
    'float': ('f', '%.2f'),
    'double': ('f', '%.2f'),
    'char': ('s', "'%s'"),
    'unsigned char': ('u', '%u'),
    'signed char': ('d', '%d'),
    'bool': ('u', '%u'),
    'int32_t': ('d', '%d'),
    'uint32_t': ('u', '%u'),
    'int16_t': ('d', '%d'),
    'uint16_t': ('u', '%u'),
    'int8_t': ('d', '%d'),
    'uint8_t': ('u', '%u'),
    'time_t': ('lld', '%lld'),
}

# Header-to-struct alias mapping for misnamed packets
# Maps: HEADER_XXX -> actual struct name in packet.h
HEADER_STRUCT_ALIASES = {
    # CG packets with non-standard naming
    "HEADER_CG_ENTERGAME": "TPacketCGEnterGame",
    "HEADER_CG_CHARACTER_POSITION": "TPacketCGPosition",
    "HEADER_CG_ADD_FLY_TARGETING": "TPacketCGFlyTargeting",
    "HEADER_CG_FLY_TARGETING": "TPacketCGFlyTargeting",
    "HEADER_CG_MYSHOP": "TPacketCGMyShop",
    "HEADER_CG_MARK_CRCLIST": "TPacketCGMarkCRCList",
    "HEADER_CG_MARK_IDXLIST": "TPacketCGMarkIDXList",
    "HEADER_CG_SYMBOL_CRC": "TPacketCGSymbolCRC",
    "HEADER_CG_STATE_CHECKER": "TPacketCGStateCheck",
    "HEADER_CG_SAFEBOX_ITEM_MOVE": "TPacketCGItemMove",
    # GC packets with non-standard naming
    "HEADER_GC_CHARACTER_DEL": "TPacketGCCharacterDelete",
    "HEADER_GC_CHARACTER_DELETE_SUCCESS": "TPacketGCDestroyCharacterSuccess",
    "HEADER_GC_CHARACTER_CREATE_FAILURE": "TPacketGCCreateFailure",
    "HEADER_GC_CHARACTER_POINTS": "TPacketGCPoints",
    "HEADER_GC_CHARACTER_POINT_CHANGE": "TPacketGCPointChange",
    "HEADER_GC_QUICKSLOT_SWAP": "TPacketGCQuickSlotSwap",
    "HEADER_GC_PVP": "TPacketGCPVP",
    "HEADER_GC_CHARACTER_POSITION": "TPacketGCPosition",
    "HEADER_GC_ADD_FLY_TARGETING": "TPacketGCFlyTargeting",
    "HEADER_GC_FLY_TARGETING": "TPacketGCFlyTargeting",
    "HEADER_GC_MARK_IDXLIST": "TPacketGCMarkIDXList",
    "HEADER_GC_SKILL_GROUP": "TPacketGCChangeSkillGroup",
    "HEADER_GC_NPC_POSITION": "TPacketGCNPCPosition",
    "HEADER_GC_SYMBOL_DATA": "TPacketGCGuildSymbolData",
    "HEADER_GC_CHAR_ADDITIONAL_INFO": "TPacketGCCharacterAdditionalInfo",
    "HEADER_GC_MAIN_CHARACTER3_BGM": "TPacketGCMainCharacter3_BGM",
    "HEADER_GC_MAIN_CHARACTER4_BGM_VOL": "TPacketGCMainCharacter4_BGM_VOL",
    "HEADER_GC_HYBRIDCRYPT_KEYS": "TPacketGCHybridCryptKeys",
    "HEADER_GC_HYBRIDCRYPT_SDB": "TPacketGCPackageSDB",
    "HEADER_GC_RESPOND_CHANNELSTATUS": "TPacketGCStateCheck",
    "HEADER_GC_REQUEST_MAKE_GUILD": "TPacketGCGuild",
}

def parse_packet_headers(content):
    """Extract HEADER_CG_* and HEADER_GC_* definitions (skip commented ones)"""
    headers = {}
    
    # Process line by line to skip commented lines
    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('//'):
            continue
        
        if '//' in line:
            line = line[:line.index('//')]
        
        pattern = r'\b(HEADER_(?:CG|GC)_\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)'
        match = re.search(pattern, line)
        if match:
            name = match.group(1)
            value = match.group(2)
            if value.startswith('0x'):
                value = int(value, 16)
            else:
                value = int(value)
            headers[name] = value
    
    return headers

def parse_struct_fields(struct_body):
    """Parse fields from a struct body"""
    fields = []
    
    struct_body = re.sub(r'//.*', '', struct_body)
    struct_body = re.sub(r'/\*.*?\*/', '', struct_body, flags=re.DOTALL)
    
    # Match multi-word types like "unsigned char", "unsigned long", "signed int"
    # Pattern: (type_modifier? type_name *?) field_name [array]? [array2]? ;
    pattern = r'((?:unsigned\s+|signed\s+)?(?:long\s+)?(?:\w+)(?:\s*\*)?)\s+(\w+)(?:\s*\[\s*(\w+|\d+)\s*\])?(?:\s*\[\s*(\w+|\d+)\s*\])?;'
    
    for match in re.finditer(pattern, struct_body):
        field_type = ' '.join(match.group(1).split())  # Normalize whitespace
        field_name = match.group(2).strip()
        array_size1 = match.group(3)
        array_size2 = match.group(4)
        
        if field_type in ['struct', 'union', 'enum']:
            continue
        if '*' in field_type and field_type != 'char*':
            continue
            
        fields.append({
            'type': field_type,
            'name': field_name,
            'array_size': array_size1,
            'array_size2': array_size2,
        })
    
    return fields

def is_header_only_struct(fields):
    """Check if struct only has a header field"""
    if len(fields) == 1:
        fname = fields[0]['name'].lower()
        if fname in ['header', 'bheader', 'cheader']:
            return True
    return False

def extract_balanced_braces(content, start_pos):
    """Extract content between balanced braces starting at start_pos (which points to '{')"""
    if content[start_pos] != '{':
        return None, start_pos
    
    depth = 0
    i = start_pos
    while i < len(content):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                return content[start_pos+1:i], i
        i += 1
    return None, start_pos

def parse_packet_structs(content):
    """Extract packet struct definitions with their fields"""
    structs = {}
    
    content_no_comments = re.sub(r'//[^\n]*', '', content)
    content_no_comments = re.sub(r'/\*.*?\*/', '', content_no_comments, flags=re.DOTALL)
    
    # First pass: parse typedef aliases (e.g., typedef TPacketX TPacketY;)
    alias_pattern = r'typedef\s+((?:T|S)Packet\w+)\s+((?:T|S)Packet\w+)\s*;'
    aliases = {}
    for match in re.finditer(alias_pattern, content_no_comments):
        source = match.group(1)
        alias = match.group(2)
        aliases[alias] = source
    
    # Pattern 1: typedef struct name { ... } TPacketXXX;
    # Use balanced brace extraction for complex bodies
    pattern1_start = r'typedef\s+struct\s+(?:\w+\s*)?\{'
    
    for match in re.finditer(pattern1_start, content_no_comments):
        brace_start = match.end() - 1
        struct_body, end_pos = extract_balanced_braces(content_no_comments, brace_start)
        if struct_body is None:
            continue
        
        # Find the struct name after the closing brace
        after_brace = content_no_comments[end_pos+1:end_pos+100]
        name_match = re.match(r'\s*((?:T|S)Packet\w+)\s*;', after_brace)
        if not name_match:
            continue
        
        struct_name = name_match.group(1)
        fields = parse_struct_fields(struct_body)
        if fields:
            structs[struct_name] = {
                'fields': fields,
                'header_only': is_header_only_struct(fields)
            }
    
    # Pattern 2: struct SPacketXXX { ... };  (non-typedef)
    pattern2_start = r'struct\s+((?:T|S)Packet\w+)\s*\{'
    
    for match in re.finditer(pattern2_start, content_no_comments):
        struct_name = match.group(1)
        if struct_name in structs:
            continue
            
        brace_start = match.end() - 1
        struct_body, end_pos = extract_balanced_braces(content_no_comments, brace_start)
        if struct_body is None:
            continue
        
        fields = parse_struct_fields(struct_body)
        if fields:
            structs[struct_name] = {
                'fields': fields,
                'header_only': is_header_only_struct(fields)
            }
    
    for alias, source in aliases.items():
        if source in structs and alias not in structs:
            structs[alias] = structs[source]
    
    return structs

def convert_to_camelcase(suffix):
    """Convert HEADER suffix to simple CamelCase: CHARACTER_ADD -> CharacterAdd"""
    parts = suffix.split('_')
    return ''.join(p.capitalize() for p in parts)

# Packets that truly have no struct definition (dynamic, deprecated, or no data)
NO_STRUCT_PACKETS = {
    "HEADER_CG_MALL_CHECKOUT",      # Uses dynamic/subheader system
    "HEADER_CG_DUNGEON",            # No separate CG struct, uses GC
    "HEADER_CG_TIME_SYNC",          # Internal/handshake
    "HEADER_GC_CHARACTER_DELETE_WRONG_SOCIAL_ID",  # Shares struct with delete
    "HEADER_GC_ATTACK",             # No separate struct
    "HEADER_GC_ITEM_DROP",          # Deprecated
    "HEADER_GC_CHARACTER_UPDATE_NEW", # Shares struct with update
    "HEADER_GC_PARTS",              # No struct
    "HEADER_GC_SAFEBOX_SET",        # Dynamic/uses item set
    "HEADER_GC_SAFEBOX_DEL",        # Dynamic
    "HEADER_GC_REFINE_INFORMATION_OLD",  # Deprecated
    "HEADER_GC_MALL_OPEN",          # No data
    "HEADER_GC_MALL_SET",           # Dynamic
    "HEADER_GC_MALL_DEL",           # Dynamic
    "HEADER_GC_TIME_SYNC",          # Internal
}

def header_to_struct_candidates(header_name):
    """Convert HEADER_CG_MOVE to potential struct names
    
    Simple pattern: HEADER_CG_XXX -> TPacketCGXxx or SPacketCGXxx
    Uses alias mapping for non-standard names.
    """
    candidates = []
    
    # Check alias mapping first (for non-standard names)
    if header_name in HEADER_STRUCT_ALIASES:
        struct_name = HEADER_STRUCT_ALIASES[header_name]
        candidates.append(struct_name)
        # Also add S variant if it's T
        if struct_name.startswith("TPacket"):
            candidates.append(struct_name.replace("TPacket", "SPacket", 1))
    
    if header_name.startswith("HEADER_CG_"):
        prefix = "CG"
        suffix = header_name.replace("HEADER_CG_", "")
    elif header_name.startswith("HEADER_GC_"):
        prefix = "GC"
        suffix = header_name.replace("HEADER_GC_", "")
    else:
        return candidates
    
    camel_suffix = convert_to_camelcase(suffix)
    
    # Standard patterns (as fallback)
    candidates.extend([
        f"TPacket{prefix}{camel_suffix}",  # TPacketCGMove
        f"SPacket{prefix}{camel_suffix}",  # SPacketCGMove
        f"TPacket{camel_suffix}",          # TPacketMove (without prefix)
        f"SPacket{camel_suffix}",          # SPacketMove
    ])
    
    return candidates

def generate_printer_function(struct_name, struct_info):
    """Generate a printer function for a struct"""
    fields = struct_info['fields']
    lines = []
    func_name = f"Print_{struct_name}"
    
    lines.append(f"inline void {func_name}(FILE* f, const void* data, int size) {{")
    lines.append(f"    const {struct_name}& p = *(const {struct_name}*)data;")
    
    format_parts = []
    args = []
    
    for field in fields:
        fname = field['name']
        ftype = field['type']
        arr_size = field['array_size']
        arr_size2 = field['array_size2']
        
        if fname.lower() in ['header', 'bheader', 'cheader']:
            continue
        
        if ftype.startswith('TPacket') or ftype.startswith('SPacket'):
            continue
        if ftype in ['TItemPos', 'TQuickslot', 'TSimplePlayer', 'TPlayerSkill', 
                     'TPlayerItemAttribute', 'TRefineMaterial', 'TEquipmentItemSet',
                     'TPacketAffectElement', 'TShopItemData', 'packet_shop_item',
                     'TLandPacketElement', 'TNPCPosition', 'TSubPacketShopTab']:
            format_parts.append(f"{fname}=(struct)")
            continue
        
        if arr_size2:
            format_parts.append(f"{fname}=(2D)")
            continue
        
        if arr_size:
            if ftype == 'char':
                format_parts.append(f"{fname}='%s'")
                args.append(f"p.{fname}")
            else:
                format_parts.append(f"{fname}=[{arr_size}]")
            continue
        
        if ftype in TYPE_FORMAT:
            fmt_spec, fmt_str = TYPE_FORMAT[ftype]
            simple_fmt = fmt_str.replace("'", "")
            format_parts.append(f"{fname}={simple_fmt}")
            
            if ftype == 'time_t':
                args.append(f"(long long)p.{fname}")
            else:
                args.append(f"p.{fname}")
        else:
            format_parts.append(f"{fname}=%u")
            args.append(f"(unsigned)p.{fname}")
    
    if format_parts and args:
        format_str = ' '.join(format_parts) + '\\n'
        args_str = ', '.join(args)
        lines.append(f'    fprintf(f, "{format_str}", {args_str});')
    elif format_parts:
        format_str = ' '.join(format_parts) + '\\n'
        lines.append(f'    fprintf(f, "{format_str}");')
    else:
        lines.append('    fprintf(f, "(header only)\\n");')
    
    lines.append("}")
    return '\n'.join(lines), func_name

def generate_short_name(header_name):
    """HEADER_CG_MOVE -> CG_MOVE"""
    return header_name.replace("HEADER_", "")

def generate_output(headers, structs):
    """Generate the PacketDebugRegGen.h file content"""
    
    cg_packets = []
    gc_packets = []
    generated_printers = {}
    printer_code = []
    
    # Stats
    stats = {
        'with_struct': 0,
        'header_only': 0,
        'variable_size': 0,
        'no_struct': 0
    }
    
    # Known variable-size packets (contain wSize field)
    variable_size_headers = set()
    for sname, sinfo in structs.items():
        for field in sinfo['fields']:
            if field['name'] in ['size', 'wSize', 'Size'] and field['type'] in ['WORD', 'DWORD', 'uint16_t']:
                variable_size_headers.add(sname)
    
    # Process each header
    for header_name, header_value in sorted(headers.items(), key=lambda x: (x[0][:9], x[1])):
        short_name = generate_short_name(header_name)
        
        found_struct = None
        for candidate in header_to_struct_candidates(header_name):
            if candidate in structs:
                found_struct = candidate
                break
        
        entry = {
            'header': header_name,
            'value': header_value,
            'name': short_name,
            'struct': found_struct,
            'printer': None,
            'comment': None
        }
        
        if found_struct:
            struct_info = structs[found_struct]
            
            if struct_info['header_only']:
                entry['comment'] = 'header only'
                stats['header_only'] += 1
            elif found_struct in variable_size_headers:
                entry['comment'] = 'variable size'
                stats['variable_size'] += 1
            else:
                stats['with_struct'] += 1
            
            if found_struct not in generated_printers:
                code, func_name = generate_printer_function(found_struct, struct_info)
                printer_code.append(code)
                generated_printers[found_struct] = func_name
            
            entry['printer'] = generated_printers[found_struct]
        elif header_name in NO_STRUCT_PACKETS:
            entry['comment'] = 'no struct (dynamic/deprecated)'
            stats['no_struct'] += 1
        else:
            entry['comment'] = 'no struct found'
            stats['no_struct'] += 1
        
        if header_name.startswith("HEADER_CG_"):
            cg_packets.append(entry)
        else:
            gc_packets.append(entry)
    
    # Generate the file
    lines = []
    lines.append("#pragma once")
    lines.append("/**")
    lines.append(" * @file PacketDebugRegGen.h")
    lines.append(" * @brief AUTO-GENERATED - Do not edit manually!")
    lines.append(" * ")
    lines.append(" * Generated by: generate_packet_debug.py")
    lines.append(" * Re-run the script after modifying packet.h")
    lines.append(" *")
    lines.append(f" * Stats: {stats['with_struct']} with struct, {stats['header_only']} header-only,")
    lines.append(f" *        {stats['variable_size']} variable-size, {stats['no_struct']} no struct found")
    lines.append(" */")
    lines.append("")
    lines.append("#ifndef __PACKET_DEBUG_REG_GEN_H__")
    lines.append("#define __PACKET_DEBUG_REG_GEN_H__")
    lines.append("")
    lines.append("#include \"../../Lead-Shared-Source/packet.h\"")
    lines.append("")
    
    # Fallback printers
    lines.append("//=============================================================================")
    lines.append("// Fallback Printers")
    lines.append("//=============================================================================")
    lines.append("inline void PrintHexDump(FILE* f, const void* data, int size) {")
    lines.append("    if (size <= 1) { fprintf(f, \"(empty)\\n\"); return; }")
    lines.append("    const BYTE* bytes = (const BYTE*)data;")
    lines.append("    int maxBytes = (size - 1 > 24) ? 24 : size - 1;")
    lines.append("    for (int i = 1; i <= maxBytes; i++) fprintf(f, \"%02X \", bytes[i]);")
    lines.append("    if (size - 1 > 24) fprintf(f, \"...\");")
    lines.append("    fprintf(f, \"\\n\");")
    lines.append("}")
    lines.append("")
    lines.append("inline void PrintHeaderOnly(FILE* f, const void* data, int size) {")
    lines.append("    fprintf(f, \"(header only)\\n\");")
    lines.append("}")
    lines.append("")
    
    # Generated printers
    lines.append("//=============================================================================")
    lines.append(f"// Auto-Generated Printer Functions ({len(printer_code)} structs)")
    lines.append("//=============================================================================")
    for code in printer_code:
        lines.append(code)
        lines.append("")
    
    # Registration
    lines.append("//=============================================================================")
    lines.append("// Auto Registration")
    lines.append("//=============================================================================")
    lines.append("inline void RegisterAllPacketsGenerated()")
    lines.append("{")
    lines.append("    auto& dbg = CPacketDebug::Instance();")
    lines.append("")
    lines.append("    //-------------------------------------------------------------------------")
    lines.append(f"    // Client -> Server (CG) - {len(cg_packets)} packets")
    lines.append("    //-------------------------------------------------------------------------")
    
    for pkt in cg_packets:
        if pkt['comment'] == 'header only':
            printer = 'PrintHeaderOnly'
        elif pkt['printer']:
            printer = pkt['printer']
        else:
            printer = 'PrintHexDump'
        
        comment = f" // {pkt['comment']}" if pkt['comment'] else ""
        lines.append(f"    dbg.RegSend({pkt['header']}, \"{pkt['name']}\", {printer});{comment}")
    
    lines.append("")
    lines.append("    //-------------------------------------------------------------------------")
    lines.append(f"    // Server -> Client (GC) - {len(gc_packets)} packets")
    lines.append("    //-------------------------------------------------------------------------")
    
    for pkt in gc_packets:
        if pkt['comment'] == 'header only':
            printer = 'PrintHeaderOnly'
        elif pkt['printer']:
            printer = pkt['printer']
        else:
            printer = 'PrintHexDump'
        
        comment = f" // {pkt['comment']}" if pkt['comment'] else ""
        lines.append(f"    dbg.RegRecv({pkt['header']}, \"{pkt['name']}\", {printer});{comment}")
    
    lines.append("}")
    lines.append("")
    lines.append("#endif // __PACKET_DEBUG_REG_GEN_H__")
    lines.append("")
    
    return "\n".join(lines)

def main():
    print(f"Reading: {PACKET_H_PATH}")
    
    if not os.path.exists(PACKET_H_PATH):
        print(f"ERROR: {PACKET_H_PATH} not found!")
        return 1
    
    with open(PACKET_H_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    headers = parse_packet_headers(content)
    structs = parse_packet_structs(content)
    
    print(f"Found {len(headers)} packet headers")
    print(f"Found {len(structs)} packet structs")
    
    cg_count = sum(1 for h in headers if h.startswith("HEADER_CG_"))
    gc_count = sum(1 for h in headers if h.startswith("HEADER_GC_"))
    print(f"  CG (Client->Server): {cg_count}")
    print(f"  GC (Server->Client): {gc_count}")
    
    output = generate_output(headers, structs)
    
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write(output)
    
    print(f"\nGenerated: {OUTPUT_PATH}")
    print("Done!")
    return 0

if __name__ == "__main__":
    exit(main())
