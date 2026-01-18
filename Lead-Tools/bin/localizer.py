import os
import re
import argparse
import time
from deep_translator import GoogleTranslator

DICTIONARY = {}
REVERSE_LOOKUP = set()
NEW_DICTIONARY_DATA = {}
TRANSLATION_CACHE = {}
CHANGELOG = []

def get_encoding(file_path, encodings):
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                f.read()
            return enc
        except Exception:
            continue
    return None

def load_dictionary(path):
    enc = get_encoding(path, ['utf-16', 'utf-8-sig', 'cp949', 'cp1252'])
    if not enc: return None

    with open(path, 'r', encoding=enc) as f:
        content = f.read()

    pattern = re.compile(r'"((?:[^"\\]|\\.)*)"\s*;\s*"((?:[^"\\]|\\.)*)"\s*;')
    matches = pattern.findall(content)

    for source, target in matches:
        clean_src = source.replace('\\"', '"')
        clean_tgt = target.replace('\\"', '"')
        DICTIONARY[clean_src] = clean_tgt
        REVERSE_LOOKUP.add(clean_tgt)
        
        if clean_src == clean_tgt:
            REVERSE_LOOKUP.add(clean_src)

    return enc

def translate_string(text):
    if text in TRANSLATION_CACHE:
        return TRANSLATION_CACHE[text]
    
    try:
        time.sleep(0.1)
        translated = GoogleTranslator(source='auto', target='en').translate(text)
        TRANSLATION_CACHE[text] = translated
        return translated
    except Exception:
        return text

def get_line_number(content, index):
    return content.count('\n', 0, index) + 1

def process_file(file_path):
    enc = get_encoding(file_path, ['cp949', 'utf-8-sig', 'cp1252', 'latin-1'])
    if not enc: return

    with open(file_path, 'r', encoding=enc) as f:
        content = f.read()

    replacements = []

    lc_pattern = re.compile(r'LC_TEXT\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)')
    for match in lc_pattern.finditer(content):
        original = match.group(1)
        lookup = original.replace('\\"', '"')
        new_text = lookup

        if lookup in DICTIONARY:
            new_text = DICTIONARY[lookup]
        elif lookup in REVERSE_LOOKUP:
            new_text = lookup
        else:
            print(f"Translating: {lookup}")
            new_text = translate_string(lookup)

        NEW_DICTIONARY_DATA[new_text] = new_text

        if new_text != lookup:
            line = get_line_number(content, match.start())
            new_text_esc = new_text.replace('"', '\\"')
            replacements.append((match.start(), match.end(), f'LC_TEXT("{new_text_esc}")'))
            CHANGELOG.append(f"{file_path}:{line} [LC_TEXT] '{lookup}' -> '{new_text}'")

    chat_pattern = re.compile(r'(ChatPacket\s*\(\s*[^,]+,\s*)(?!LC_TEXT)"((?:[^"\\]|\\.)*)"')
    for match in chat_pattern.finditer(content):
        prefix = match.group(1)
        original = match.group(2)
        lookup = original.replace('\\"', '"')
        new_text = lookup

        if lookup in DICTIONARY:
            new_text = DICTIONARY[lookup]
        elif lookup in REVERSE_LOOKUP:
            new_text = lookup
        else:
            print(f"Translating: {lookup}")
            new_text = translate_string(lookup)

        NEW_DICTIONARY_DATA[new_text] = new_text

        line = get_line_number(content, match.start())
        new_text_esc = new_text.replace('"', '\\"')
        replacements.append((match.start(), match.end(), f'{prefix}LC_TEXT("{new_text_esc}")'))
        CHANGELOG.append(f"{file_path}:{line} [ChatPacket] '{lookup}' -> '{new_text}'")

    if replacements:
        replacements.sort(key=lambda x: x[0], reverse=True)
        content_list = list(content)
        for start, end, text in replacements:
            content_list[start:end] = text
        
        with open(file_path, 'w', encoding=enc) as f:
            f.write("".join(content_list))

def save_dictionary(path, encoding):
    try:
        with open(path, 'w', encoding=encoding) as f:
            for key in sorted(NEW_DICTIONARY_DATA.keys()):
                val = NEW_DICTIONARY_DATA[key]
                k_esc = key.replace('"', '\\"')
                v_esc = val.replace('"', '\\"')
                f.write(f'"{k_esc}";\n"{v_esc}";\n\n')
    except Exception as e:
        print(f"Error saving dictionary: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dictionary", help="Path to locale_string.txt")
    parser.add_argument("target_dir", help="Source code directory")
    args = parser.parse_args()

    if not os.path.exists(args.dictionary) or not os.path.exists(args.target_dir):
        return

    dict_enc = load_dictionary(args.dictionary)
    if not dict_enc: return

    print("Processing files...")
    
    for root, dirs, files in os.walk(args.target_dir):
        for file in files:
            path = os.path.join(root, file)
            if os.path.abspath(path) == os.path.abspath(args.dictionary): continue
            
            if file.lower().endswith(('.cpp', '.h', '.c', '.hpp', '.cc')):
                try:
                    with open(path, 'rb') as f:
                        if b'\0' in f.read(1024): continue
                except: continue
                
                process_file(path)

    print("Updating dictionary (Cleanup & Remap)...")
    save_dictionary(args.dictionary, dict_enc)

    if CHANGELOG:
        with open("changelog.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(CHANGELOG))
        print(f"Done. {len(CHANGELOG)} changes logged.")
    else:
        print("Done. No changes made.")

if __name__ == "__main__":
    main()
