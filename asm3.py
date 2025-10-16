import struct
import sys
import traceback

# === Глобальные данные ===
INSTRUCTIONS = {
    "переместить": {"code": b"\x48\x89", "type": "reg_reg"},
    "переместить_имм": {"code": None, "type": "reg_imm"},
    "прибавить": {"code": b"\x48\x01", "type": "reg_reg"},
    "вычесть": {"code": b"\x48\x29", "type": "reg_reg"},
    "вызвать": {"code": b"\xE8", "type": "call"},
    "вернуться": {"code": b"\xC3", "type": "none"},
    "вызов_системы": {"code": b"\x0F\x05", "type": "none"},
    "сравнить": {"code": b"\x48\x39", "type": "reg_reg"},
    "переход": {"code": b"\xE9", "type": "jmp"},
    "переход_если_равно": {"code": b"\x0F\x84", "type": "jcc"},
    "переход_если_неравно": {"code": b"\x0F\x85", "type": "jcc"},
    "втолкнуть": {"code": b"\x50", "type": "push"},
    "вытолкнуть": {"code": b"\x58", "type": "pop"},
    "нет_операции": {"code": b"\x90", "type": "none"},
    "остановить": {"code": b"\xF4", "type": "none"},
}

REGISTERS = {
    "рвх": 0, "рсх": 1, "рдх": 2, "рбх": 3,
    "рсп": 4, "рбп": 5, "рис": 6, "рди": 7,
    "р8": 8, "р9": 9, "р10": 10, "р11": 11,
    "р12": 12, "р13": 13, "р14": 14, "р15": 15
}

# Глобальное состояние ассемблера
labels = {}
label_sections = {}
symbols = {}
sections = {".text": bytearray(), ".data": bytearray()}
current_section = ".text"
entry_point = "_start"
position = {".text": 0, ".data": 0}
pass_num = 0
code_start = 0x400000

# ELF layout
text_size = 0
data_size = 0
vaddr_text = 0
vaddr_data = 0
offset_text = 0
offset_data = 0
memsz_text = 0
memsz_data = 0

# Логи
log_file = None
tokens_log = None

# === Вспомогательные функции ===

def log(message):
    log_file.write(message + "\n")
    log_file.flush()

def log_tokens(line_num, tokens):
    tokens_log.write(f"Line {line_num}: {tokens}\n")
    tokens_log.flush()

def close_log():
    log_file.close()
    tokens_log.close()

def log_labels():
    log("=== Метки и их адреса ===")
    for label, pos in labels.items():
        section = label_sections.get(label, "неизвестно")
        base_addr = vaddr_text if section == ".text" else vaddr_data
        abs_addr = base_addr + pos
        value = symbols.get(label, "N/A")
        log(f"Метка '{label}': секция = {section}, позиция = {pos}, абсолютный адрес = {hex(abs_addr)}, значение = {value}")

def align_up(x, align):
    return (x + align - 1) & ~(align - 1)

# === Лексер ===

def tokenize_line(line):
    semi = line.find(';')
    if semi != -1:
        line = line[:semi]
    line = line.rstrip()
    if not line:
        return []
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '"':
            i += 1
            s = ''
            while i < n and line[i] != '"':
                if line[i] == '\\' and i + 1 < n:
                    i += 1
                    esc = line[i]
                    if esc == 'n':
                        s += '\n'
                    elif esc == 't':
                        s += '\t'
                    elif esc == '"':
                        s += '"'
                    elif esc == '\\':
                        s += '\\'
                    else:
                        s += '\\' + esc
                    i += 1
                else:
                    s += line[i]
                    i += 1
            if i >= n:
                raise ValueError("Незакрытая кавычка")
            i += 1
            tokens.append(('string', s))
            continue
        if ch == ',':
            tokens.append(('comma', ','))
            i += 1
            continue
        if ch == ':':
            tokens.append(('colon', ':'))
            i += 1
            continue
        j = i
        while j < n and not (line[j].isspace() or line[j] in ',:;'):
            j += 1
        word = line[i:j]
        if word:
            tokens.append(('word', word))
        i = j
    return tokens

# === Парсинг ===

def parse_operand(operand):
    if operand.isdigit():
        return int(operand)
    if operand.startswith("0x"):
        return int(operand, 16)
    if operand in labels:
        section = label_sections[operand]
        base_addr = vaddr_text if section == ".text" else vaddr_data
        return labels[operand] + base_addr
    if operand in symbols:
        return symbols[operand]
    raise ValueError(f"Неизвестный операнд: {operand}")

def parse_number_token(token):
    if token[0] != 'word':
        raise ValueError(f"Ожидалось число, получено: {token}")
    s = token[1]
    if s.isdigit():
        return int(s)
    if s.startswith("0x"):
        return int(s, 16)
    raise ValueError(f"Недопустимое число: {s}")

def encode_instruction(mnemonic, operands):
    instr = INSTRUCTIONS[mnemonic]
    code = bytearray()
    if instr["type"] == "none":
        code.extend(instr["code"])
    elif instr["type"] == "reg_reg" and len(operands) == 2:
        dst = REGISTERS.get(operands[0])
        src = REGISTERS.get(operands[1])
        if dst is None or src is None:
            raise ValueError(f"Неверные регистры: {operands}")
        code.extend(instr["code"])
        modrm = 0xC0 | (src << 3) | dst
        code.append(modrm)
    elif instr["type"] == "reg_imm" and len(operands) == 2:
        reg = REGISTERS.get(operands[0])
        if reg is None:
            raise ValueError(f"Неверный регистр: {operands}")
        imm = parse_operand(operands[1])
        if 0 <= reg <= 7:
            code.extend(b'\x48')
            code.append(0xB8 + reg)
            code.extend(struct.pack("<Q", imm))
        elif 8 <= reg <= 15:
            code.extend(b'\x49')
            code.append(0xB8 + (reg - 8))
            code.extend(struct.pack("<Q", imm))
        else:
            raise ValueError("Регистры вне диапазона")
    elif instr["type"] in ("call", "jmp") and len(operands) == 1:
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 5)
        code.extend(struct.pack("<i", offset))
    elif instr["type"] == "jcc" and len(operands) == 1:
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 6)
        code.extend(struct.pack("<i", offset))
    elif instr["type"] == "push" and len(operands) == 1:
        reg = REGISTERS.get(operands[0])
        if reg == 0:
            code.extend(instr["code"])
        else:
            raise ValueError("Поддерживается только push рвх")
    elif instr["type"] == "pop" and len(operands) == 1:
        reg = REGISTERS.get(operands[0])
        if reg == 0:
            code.extend(instr["code"])
        else:
            raise ValueError("Поддерживается только pop рвх")
    else:
        raise ValueError(f"Неподдерживаемые операнды для {mnemonic}: {operands}")
    return bytes(code)

def parse_instruction_or_directive(tokens):
    global current_section, entry_point
    first = tokens[0]
    if first[0] != 'word':
        raise ValueError(f"Ожидалось слово, получено: {first}")
    word = first[1]
    if word.startswith('.'):
        if word == '.текст':
            current_section = ".text"
        elif word == '.данные':
            current_section = ".data"
        elif word == '.глобал':
            if len(tokens) < 2 or tokens[1][0] != 'word':
                raise ValueError(".глобал требует имя метки")
            entry_point = tokens[1][1]
        elif word == '.константа':
            if len(tokens) < 3:
                raise ValueError(".константа требует имя и значение")
            name = tokens[1][1]
            value = parse_number_token(tokens[2])
            symbols[name] = value
        elif word == '.строка_нуль' or word == '.строка':
            if len(tokens) < 2 or tokens[1][0] != 'string':
                raise ValueError(f"{word} требует строку в кавычках")
            if current_section != ".data":
                raise ValueError("Строки разрешены только в секции .data")
            s = tokens[1][1]
            bstring = s.encode('utf-8')
            add_null = (word == '.строка_нуль')
            size = len(bstring) + (1 if add_null else 0)
            if pass_num == 1:
                position[".data"] += size
            elif pass_num == 3:
                sections[".data"] += bstring
                if add_null:
                    sections[".data"] += b'\x00'
                position[".data"] += size
        else:
            raise ValueError(f"Неизвестная директива: {word}")
        return
    mnemonic = word
    if mnemonic not in INSTRUCTIONS:
        raise ValueError(f"Неизвестная инструкция: {mnemonic}")
    operands = []
    for tok in tokens[1:]:
        if tok[0] == 'word':
            operands.append(tok[1])
        elif tok[0] == 'comma':
            continue
        else:
            raise ValueError(f"Недопустимый токен в операндах: {tok}")
    if pass_num == 3:
        code = encode_instruction(mnemonic, operands)
        sections[current_section] += code
        position[current_section] += len(code)
    else:
        instr_info = INSTRUCTIONS[mnemonic]
        if instr_info["type"] == "reg_imm" and len(operands) == 2:
            position[current_section] += 10
        elif instr_info["type"] in ("reg_reg",) and len(operands) == 2:
            position[current_section] += 3
        elif instr_info["type"] in ("call", "jmp") and len(operands) == 1:
            position[current_section] += 5
        elif instr_info["type"] == "jcc" and len(operands) == 1:
            position[current_section] += 6
        elif instr_info["type"] in ("push", "pop") and len(operands) == 1:
            position[current_section] += 1
        elif instr_info["type"] == "none" and len(operands) == 0:
            position[current_section] += len(instr_info["code"])
        else:
            raise ValueError(f"Неподдерживаемые операнды для {mnemonic}: {operands}")

def parse_tokens(tokens):
    if not tokens:
        return
    if len(tokens) >= 2 and tokens[0][0] == 'word' and tokens[1][0] == 'colon':
        label = tokens[0][1]
        labels[label] = position[current_section]
        label_sections[label] = current_section
        rest = tokens[2:]
        if rest:
            parse_instruction_or_directive(rest)
        return
    parse_instruction_or_directive(tokens)

def parse(source):
    global pass_num, text_size, data_size, vaddr_text, vaddr_data
    global offset_text, offset_data, memsz_text, memsz_data
    global sections, position

    lines = source.split('\n')

    # === PASS 1 ===
    pass_num = 1
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    log(f"=== PASS {pass_num} START ===")
    for line_num, line in enumerate(lines, start=1):
        log(f"[PASS {pass_num}] Line {line_num}: {line.strip()}")
        try:
            tokens = tokenize_line(line)
            log_tokens(line_num, tokens)
            parse_tokens(tokens)
        except Exception as e:
            log(f"ERROR on pass {pass_num}, line {line_num}: {str(e)}")
            log(traceback.format_exc())
            raise

    text_size = position[".text"]
    data_size = position[".data"]
    PAGE_SIZE = 0x1000
    elf_header_size = 64
    program_header_size = 56
    ph_num = 2
    ph_table_size = program_header_size * ph_num
    offset_text = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
    offset_data = align_up(offset_text + text_size, PAGE_SIZE)
    vaddr_text = code_start
    memsz_text = align_up(text_size, PAGE_SIZE)
    vaddr_data = align_up(vaddr_text + memsz_text, PAGE_SIZE)
    memsz_data = align_up(data_size, PAGE_SIZE)
    log(f"Calculated addresses:")
    log(f".text offset = {hex(offset_text)}, vaddr = {hex(vaddr_text)}, size = {text_size}, memsz = {memsz_text}")
    log(f".data offset = {hex(offset_data)}, vaddr = {hex(vaddr_data)}, size = {data_size}, memsz = {memsz_data}")

    # === PASS 3 ===
    pass_num = 3
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    log(f"=== PASS {pass_num} START ===")
    for line_num, line in enumerate(lines, start=1):
        log(f"[PASS {pass_num}] Line {line_num}: {line.strip()}")
        try:
            tokens = tokenize_line(line)
            parse_tokens(tokens)
        except Exception as e:
            log(f"ERROR on pass {pass_num}, line {line_num}: {str(e)}")
            log(traceback.format_exc())
            raise

    log_labels()

# === ELF ===

def create_elf(filename):
    global sections, entry_point, labels, vaddr_text
    text = sections[".text"]
    data = sections[".data"]
    entry_addr = vaddr_text + labels.get(entry_point, 0)
    elf_header_size = 64
    program_header_size = 56
    ph_num = 2
    ph_table_size = program_header_size * ph_num
    file_content = bytearray()
    elf_header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        2, 0x3E, 1, entry_addr, elf_header_size, 0, 0,
        elf_header_size, program_header_size, ph_num, 0, 0, 0,
    )
    text_header = struct.pack(
        "<IIQQQQQQ",
        1, 5, offset_text, vaddr_text, vaddr_text,
        len(text), memsz_text, 0x1000,
    )
    data_header = struct.pack(
        "<IIQQQQQQ",
        1, 6, offset_data, vaddr_data, vaddr_data,
        len(data), memsz_data, 0x1000,
    )
    file_content.extend(elf_header)
    file_content.extend(text_header)
    file_content.extend(data_header)
    if len(file_content) < offset_text:
        file_content.extend(b'\x00' * (offset_text - len(file_content)))
    file_content.extend(text)
    if len(file_content) < offset_data:
        file_content.extend(b'\x00' * (offset_data - len(file_content)))
    file_content.extend(data)
    with open(filename, "wb") as f:
        f.write(file_content)
    import os
    os.chmod(filename, 0o755)

# === Основной запуск (без if __name__ == "__main__") ===

if len(sys.argv) != 2:
    print("Использование: python asm2_flat.py <файл.квс>")
    sys.exit(1)

source_file = sys.argv[1]
if not source_file.endswith('.квс'):
    print("Ошибка: файл должен иметь расширение .квс")
    sys.exit(1)

try:
    with open(source_file, "r", encoding="utf-8") as f:
        source = f.read()
except FileNotFoundError:
    print(f"Ошибка: файл '{source_file}' не найден.")
    sys.exit(1)
except UnicodeDecodeError as e:
    print(f"Ошибка кодировки в файле '{source_file}': {e}")
    sys.exit(1)

# Инициализация логов
log_file = open("asm_log.txt", "w", encoding="utf-8")
tokens_log = open("tokens.log", "w", encoding="utf-8")

try:
    parse(source)
    elf_file = source_file[:-4] + ".elf"
    create_elf(elf_file)
    close_log()
    print(f"ELF-файл успешно создан: {elf_file}")
    print("Токены сохранены в tokens.log")
    print(f"Запустите: ./{elf_file}")
except Exception as e:
    close_log()
    print(f"Ошибка ассемблирования: {str(e)}")
    sys.exit(1)
