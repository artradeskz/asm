import struct
import sys
import traceback

# === Глобальные данные ===
INSTRUCTIONS = {
    # Базовые
    "переместить": {"code": 0x88, "type": "mov", "size": "varied"},
    "переместить_имм": {"code": 0xB0, "type": "mov_imm", "size": "varied"},
    "прибавить": {"code": 0x00, "type": "alu", "size": 2},
    "вычесть": {"code": 0x28, "type": "alu", "size": 2},
    "вызвать": {"code": 0xE8, "type": "call", "size": 5},
    "вернуться": {"code": 0xC3, "type": "none", "size": 1},
    "вызов_системы": {"code": 0x0F05, "type": "syscall", "size": 2},
    "сравнить": {"code": 0x38, "type": "alu", "size": 2},
    "переход": {"code": 0xE9, "type": "jmp", "size": 5},
    "переход_если_равно": {"code": 0x0F84, "type": "jcc", "size": 6},
    "переход_если_неравно": {"code": 0x0F85, "type": "jcc", "size": 6},
    "втолкнуть": {"code": 0x50, "type": "push", "size": 1},
    "вытолкнуть": {"code": 0x58, "type": "pop", "size": 1},
    "нет_операции": {"code": 0x90, "type": "none", "size": 1},
    "остановить": {"code": 0xF4, "type": "none", "size": 1},

    # Арифметика
    "увеличить": {"code": 0xFE, "subop": 0, "type": "incdec", "size": 2},
    "уменьшить": {"code": 0xFE, "subop": 1, "type": "incdec", "size": 2},
    "отрицать": {"code": 0xF6, "subop": 3, "type": "unary", "size": 2},
    "умножить": {"code": 0xF6, "subop": 4, "type": "muldiv", "size": 2},
    "разделить": {"code": 0xF6, "subop": 6, "type": "muldiv", "size": 2},

    # Логика
    "и": {"code": 0x20, "type": "alu", "size": 2},
    "или": {"code": 0x08, "type": "alu", "size": 2},
    "исключающее_или": {"code": 0x30, "type": "alu", "size": 2},
    "инвертировать": {"code": 0xF6, "subop": 2, "type": "unary", "size": 2},
    "проверить": {"code": 0x84, "type": "test", "size": 2},

    # Адресация
    "загрузить_адрес": {"code": 0x8D, "type": "lea", "size": 4},

    # Сдвиги
    "сдвиг_влево": {"code": 0xC0, "subop": 4, "type": "shift", "size": 3},
    "сдвиг_вправо": {"code": 0xC0, "subop": 5, "type": "shift", "size": 3},

    # Флаги
    "установить_перенос": {"code": 0xF9, "type": "none", "size": 1},
    "сбросить_перенос": {"code": 0xF8, "type": "none", "size": 1},

    # Прерывания
    "прервать": {"code": 0xCD, "type": "int", "size": 2},
}

REGISTERS = {
    "рвх": {"code": 0, "size": 64}, "рсх": {"code": 1, "size": 64}, 
    "рдх": {"code": 2, "size": 64}, "рбх": {"code": 3, "size": 64},
    "рсп": {"code": 4, "size": 64}, "рбп": {"code": 5, "size": 64}, 
    "рис": {"code": 6, "size": 64}, "рди": {"code": 7, "size": 64},
    "ал": {"code": 0, "size": 8}, "кл": {"code": 1, "size": 8},
    "дл": {"code": 2, "size": 8}, "бл": {"code": 3, "size": 8},
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
    tokens_log.write("Line " + str(line_num) + ": " + str(tokens) + "\n")
    tokens_log.flush()

def close_log():
    if log_file:
        log_file.close()
    if tokens_log:
        tokens_log.close()

def log_labels():
    log("=== Метки и их адреса ===")
    for label, pos in labels.items():
        section = label_sections.get(label, "неизвестно")
        base_addr = vaddr_text if section == ".text" else vaddr_data
        abs_addr = base_addr + pos
        value = symbols.get(label, "N/A")
        log("Метка '" + label + "': секция = " + section +
            ", позиция = " + str(pos) +
            ", абсолютный адрес = " + hex(abs_addr) +
            ", значение = " + str(value))

def align_up(x, align):
    return (x + align - 1) & ~(align - 1)

def get_register_info(reg_name):
    """Получить информацию о регистре"""
    if reg_name in REGISTERS:
        return REGISTERS[reg_name]
    raise ValueError(f"Неизвестный регистр: {reg_name}")

def encode_modrm(mod, reg, rm):
    """Закодировать байт ModR/M"""
    return (mod << 6) | (reg << 3) | rm

def encode_sib(scale, index, base):
    """Закодировать байт SIB"""
    return (scale << 6) | (index << 3) | base

# === Лексер ===

def tokenize_line(line):
    semi = line.find(';')
    if semi != -1:
        line = line[:semi]
    line = line.strip()
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
            
        if ch == '[':
            # Обработка выражений в скобках
            i += 1
            expr = ''
            while i < n and line[i] != ']':
                expr += line[i]
                i += 1
            if i >= n:
                raise ValueError("Незакрытая скобка")
            i += 1
            tokens.append(('memory', expr))
            continue
            
        j = i
        while j < n and not (line[j].isspace() or line[j] in ',:;[]'):
            j += 1
        word = line[i:j]
        if word:
            # Определяем тип токена
            if word.startswith('0x'):
                tokens.append(('hex', word))
            elif word.isdigit():
                tokens.append(('number', word))
            elif word in REGISTERS:
                tokens.append(('register', word))
            else:
                tokens.append(('word', word))
        i = j
        
    return tokens

# === Парсинг ===

def parse_operand(operand):
    """Парсинг операнда с поддержкой меток и чисел"""
    if isinstance(operand, int):
        return operand
        
    if operand in labels:
        section = label_sections[operand]
        base_addr = vaddr_text if section == ".text" else vaddr_data
        return labels[operand] + base_addr
        
    if operand in symbols:
        return symbols[operand]
        
    if operand.startswith("0x"):
        return int(operand, 16)
        
    if operand.isdigit():
        return int(operand)
        
    # Попробовать как выражение
    try:
        return eval(operand, {"__builtins__": None}, {})
    except:
        raise ValueError(f"Неизвестный операнд: {operand}")

def parse_number_token(token):
    if token[0] in ('number', 'hex'):
        s = token[1]
        if s.startswith("0x"):
            return int(s, 16)
        else:
            return int(s)
    raise ValueError(f"Ожидалось число, получено: {token[0]}")

def encode_instruction(mnemonic, operands):
    instr = INSTRUCTIONS[mnemonic]
    code = bytearray()
    itype = instr["type"]

    if itype == "none":
        if isinstance(instr["code"], int):
            code.append(instr["code"])
        else:
            code.extend(struct.pack("<H", instr["code"]))

    elif itype == "mov":
        # mov reg, reg/mem/imm
        if len(operands) != 2:
            raise ValueError("MOV требует 2 операнда")
            
        dst = operands[0]
        src = operands[1]
        
        dst_reg = get_register_info(dst)
        
        # MOV reg, imm
        if src not in REGISTERS and not src.startswith('['):
            imm = parse_operand(src)
            if dst_reg["size"] == 64:
                code.append(0x48)  # REX.W
                code.append(0xB8 + dst_reg["code"])
                code.extend(struct.pack("<Q", imm))
            elif dst_reg["size"] == 8:
                code.append(0xB0 + dst_reg["code"])
                code.extend(struct.pack("<B", imm & 0xFF))
                
        # MOV reg, reg
        elif src in REGISTERS:
            src_reg = get_register_info(src)
            if dst_reg["size"] == 64 and src_reg["size"] == 64:
                code.append(0x48)  # REX.W
                code.append(0x89)
                code.append(encode_modrm(3, src_reg["code"], dst_reg["code"]))
            else:
                raise ValueError("Разные размеры регистров не поддерживаются")

    elif itype == "mov_imm":
        # mov reg, immediate
        if len(operands) != 2:
            raise ValueError("MOV_IMM требует 2 операнда")
            
        reg = get_register_info(operands[0])
        imm = parse_operand(operands[1])
        
        if reg["size"] == 64:
            code.append(0x48)  # REX.W
            code.append(instr["code"] + reg["code"])
            code.extend(struct.pack("<Q", imm))
        elif reg["size"] == 8:
            code.append(instr["code"] + reg["code"])
            code.extend(struct.pack("<B", imm & 0xFF))

    elif itype == "alu":
        # add, sub, and, or, xor, cmp
        if len(operands) != 2:
            raise ValueError("ALU операция требует 2 операнда")
            
        dst = get_register_info(operands[0])
        src = get_register_info(operands[1])
        
        if dst["size"] == 64 and src["size"] == 64:
            code.append(0x48)  # REX.W
            code.append(instr["code"])
            code.append(encode_modrm(3, src["code"], dst["code"]))
        else:
            raise ValueError("64-битные регистры требуются")

    elif itype == "call" or itype == "jmp":
        if len(operands) != 1:
            raise ValueError(f"{mnemonic.upper()} требует 1 операнд")
            
        code.append(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 5)
        code.extend(struct.pack("<i", offset))

    elif itype == "jcc":
        if len(operands) != 1:
            raise ValueError("Условный переход требует 1 операнд")
            
        code.extend(struct.pack("<H", instr["code"]))
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 6)
        code.extend(struct.pack("<i", offset))

    elif itype == "push" or itype == "pop":
        if len(operands) != 1:
            raise ValueError(f"{mnemonic.upper()} требует 1 операнд")
            
        reg = get_register_info(operands[0])
        if reg["size"] == 64:
            code.append(instr["code"] + reg["code"])
        else:
            raise ValueError("PUSH/POP требуют 64-битные регистры")

    elif itype == "incdec":
        if len(operands) != 1:
            raise ValueError("INC/DEC требует 1 операнд")
            
        reg = get_register_info(operands[0])
        if reg["size"] == 64:
            code.append(0x48)  # REX.W
            code.append(instr["code"])
            code.append(encode_modrm(3, instr["subop"], reg["code"]))
        else:
            raise ValueError("64-битные регистры требуются")

    elif itype == "unary":
        if len(operands) != 1:
            raise ValueError("Унарная операция требует 1 операнд")
            
        reg = get_register_info(operands[0])
        if reg["size"] == 64:
            code.append(0x48)  # REX.W
            code.append(instr["code"])
            code.append(encode_modrm(3, instr["subop"], reg["code"]))
        else:
            raise ValueError("64-битные регистры требуются")

    elif itype == "test":
        if len(operands) != 2:
            raise ValueError("TEST требует 2 операнда")
            
        dst = get_register_info(operands[0])
        src = get_register_info(operands[1])
        
        if dst["size"] == 64 and src["size"] == 64:
            code.append(0x48)  # REX.W
            code.append(instr["code"])
            code.append(encode_modrm(3, src["code"], dst["code"]))
        else:
            raise ValueError("64-битные регистры требуются")

    elif itype == "lea":
        if len(operands) != 2:
            raise ValueError("LEA требует 2 операнда")
            
        dst = get_register_info(operands[0])
        # Упрощенная LEA - только загрузка адреса метки
        addr = parse_operand(operands[1])
        
        if dst["size"] == 64:
            code.append(0x48)  # REX.W
            code.append(0x8D)  # LEA
            # Упрощенная кодировка - предполагаем прямую адресацию
            code.append(encode_modrm(0, dst["code"], 5))  # disp32
            code.extend(struct.pack("<I", addr & 0xFFFFFFFF))
        else:
            raise ValueError("LEA требует 64-битный регистр")

    elif itype == "shift":
        if len(operands) != 2:
            raise ValueError("Сдвиг требует 2 операнда")
            
        reg = get_register_info(operands[0])
        imm = parse_operand(operands[1])
        
        if reg["size"] == 64:
            code.append(0x48)  # REX.W
            code.append(0xC1)  # SHIFT
            code.append(encode_modrm(3, instr["subop"], reg["code"]))
            code.append(imm & 0xFF)
        else:
            raise ValueError("64-битные регистры требуются")

    elif itype == "int":
        if len(operands) != 1:
            raise ValueError("INT требует 1 операнд")
            
        imm = parse_operand(operands[0])
        if not (0 <= imm <= 255):
            raise ValueError("Номер прерывания должен быть 0-255")
        code.append(instr["code"])
        code.append(imm & 0xFF)

    elif itype == "syscall":
        code.extend(struct.pack("<H", instr["code"]))

    else:
        raise ValueError(f"Неизвестный тип инструкции: {itype}")

    return bytes(code)

def parse_instruction_or_directive(tokens):
    global current_section, entry_point
    first = tokens[0]
    if first[0] != 'word':
        raise ValueError("Ожидалось слово, получено: " + str(first))
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
                raise ValueError(word + " требует строку в кавычках")
            if current_section != ".data":
                raise ValueError("Строки разрешены только в секции .data")
            s = tokens[1][1]
            bstring = s.encode('utf-8')
            add_null = (word == '.строка_нуль')
            size = len(bstring) + (1 if add_null else 0)
            if pass_num == 1:
                position[".data"] += size
            elif pass_num == 2:
                sections[".data"] += bstring
                if add_null:
                    sections[".data"] += b'\x00'
                position[".data"] += size
        elif word == '.квд':  # quad word
            if len(tokens) < 2:
                raise ValueError(".квд требует значение")
            value = parse_number_token(tokens[1])
            size = 8
            if pass_num == 1:
                position[".data"] += size
            elif pass_num == 2:
                sections[".data"] += struct.pack("<Q", value)
                position[".data"] += size
        else:
            raise ValueError("Неизвестная директива: " + word)
        return

    mnemonic = word
    if mnemonic not in INSTRUCTIONS:
        raise ValueError("Неизвестная инструкция: " + mnemonic)

    operands = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok[0] == 'comma':
            i += 1
            continue
        elif tok[0] in ('word', 'register', 'number', 'hex', 'memory'):
            operands.append(tok[1])
            i += 1
        else:
            raise ValueError("Недопустимый токен в операндах: " + str(tok))

    if pass_num == 2:
        code = encode_instruction(mnemonic, operands)
        sections[current_section] += code
        position[current_section] += len(code)
    else:
        # На первом проходе просто считаем размер
        instr_info = INSTRUCTIONS[mnemonic]
        if instr_info["size"] == "varied":
            # Для инструкций переменного размера используем приблизительный размер
            if mnemonic.startswith("переместить"):
                position[current_section] += 10  # Максимальный размер для mov
            else:
                position[current_section] += 4
        else:
            position[current_section] += instr_info["size"]

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
    global sections, position, labels, label_sections

    lines = source.split('\n')

    # === ПРОХОД 1: анализ ===
    pass_num = 1
    labels.clear()
    label_sections.clear()
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    
    log("=== ПРОХОД 1: анализ ===")
    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith(';'):
            continue
            
        log("[ПРОХОД 1] Line " + str(line_num) + ": " + line)
        try:
            tokens = tokenize_line(line)
            log_tokens(line_num, tokens)
            parse_tokens(tokens)
        except Exception as e:
            log("ОШИБКА на проходе 1, строка " + str(line_num) + ": " + str(e))
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
    
    log("Вычисленные адреса:")
    log(".text offset = " + hex(offset_text) + ", vaddr = " + hex(vaddr_text) +
        ", size = " + str(text_size) + ", memsz = " + str(memsz_text))
    log(".data offset = " + hex(offset_data) + ", vaddr = " + hex(vaddr_data) +
        ", size = " + str(data_size) + ", memsz = " + str(memsz_data))

    # === ПРОХОД 2: генерация ===
    pass_num = 2
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    
    log("=== ПРОХОД 2: генерация ===")
    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith(';'):
            continue
            
        log("[ПРОХОД 2] Line " + str(line_num) + ": " + line)
        try:
            tokens = tokenize_line(line)
            parse_tokens(tokens)
        except Exception as e:
            log("ОШИБКА на проходе 2, строка " + str(line_num) + ": " + str(e))
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
    
    # ELF header
    elf_header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # e_ident
        2,  # e_type: ET_EXEC
        0x3E,  # e_machine: EM_X86_64
        1,  # e_version: EV_CURRENT
        entry_addr,  # e_entry
        elf_header_size,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        elf_header_size,  # e_ehsize
        program_header_size,  # e_phentsize
        ph_num,  # e_phnum
        0,  # e_shentsize
        0,  # e_shnum
        0   # e_shstrndx
    )
    
    # Program headers
    text_header = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type: PT_LOAD
        5,  # p_flags: R-X
        offset_text,  # p_offset
        vaddr_text,  # p_vaddr
        vaddr_text,  # p_paddr
        len(text),  # p_filesz
        memsz_text,  # p_memsz
        0x1000,  # p_align
    )
    
    data_header = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type: PT_LOAD
        6,  # p_flags: RW-
        offset_data,  # p_offset
        vaddr_data,  # p_vaddr
        vaddr_data,  # p_paddr
        len(data),  # p_filesz
        memsz_data,  # p_memsz
        0x1000,  # p_align
    )
    
    file_content.extend(elf_header)
    file_content.extend(text_header)
    file_content.extend(data_header)
    
    # Выравнивание
    file_content.extend(b'\x00' * (offset_text - len(file_content)))
    file_content.extend(text)
    file_content.extend(b'\x00' * (offset_data - len(file_content)))
    file_content.extend(data)

    with open(filename, "wb") as f_out:
        f_out.write(file_content)

    import os
    os.chmod(filename, 0o755)

# === Основной запуск ===

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python asm3_fixed.py <файл.квс>")
        sys.exit(1)

    source_file = sys.argv[1]
    if not source_file.endswith('.квс'):
        print("Ошибка: файл должен иметь расширение .квс")
        sys.exit(1)

    try:
        with open(source_file, "r", encoding="utf-8") as f_in:
            source = f_in.read()
    except FileNotFoundError:
        print("Ошибка: файл '" + source_file + "' не найден.")
        sys.exit(1)
    except UnicodeDecodeError as e:
        print("Ошибка кодировки в файле '" + source_file + "': " + str(e))
        sys.exit(1)

    log_file = open("asm_log.txt", "w", encoding="utf-8")
    tokens_log = open("tokens.log", "w", encoding="utf-8")

    try:
        parse(source)
        elf_file = source_file[:-4] + ".elf"
        create_elf(elf_file)
        close_log()
        print("ELF-файл успешно создан: " + elf_file)
        print("Токены сохранены в tokens.log")
        print("Запустите: ./" + elf_file)
    except Exception as e:
        close_log()
        print("Ошибка ассемблирования: " + str(e))
        traceback.print_exc()
        sys.exit(1) 