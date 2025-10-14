import struct
import sys
import traceback

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

class X64RussianAssembler:
    def __init__(self):
        self.labels = {}
        self.label_sections = {}
        self.symbols = {}
        self.sections = {".text": bytearray(), ".data": bytearray()}
        self.current_section = ".text"
        self.entry_point = "_start"
        self.position = {".text": 0, ".data": 0}
        self.pass_num = 0
        self.code_start = 0x400000
        self.log_file = open("asm_log.txt", "w", encoding="utf-8")
        self.tokens_log = open("tokens.log", "w", encoding="utf-8")
        # Для трёх проходов
        self.text_size = 0
        self.data_size = 0
        self.vaddr_text = 0
        self.vaddr_data = 0
        self.offset_text = 0
        self.offset_data = 0
        self.memsz_text = 0
        self.memsz_data = 0

    def log(self, message):
        self.log_file.write(message + "\n")
        self.log_file.flush()

    def log_tokens(self, line_num, tokens):
        self.tokens_log.write(f"Line {line_num}: {tokens}\n")
        self.tokens_log.flush()

    def close_log(self):
        self.log_file.close()
        self.tokens_log.close()

    def log_labels(self):
        self.log("=== Метки и их адреса ===")
        for label, pos in self.labels.items():
            section = self.label_sections.get(label, "неизвестно")
            base_addr = self.vaddr_text if section == ".text" else self.vaddr_data
            abs_addr = base_addr + pos
            value = self.symbols.get(label, "N/A")
            self.log(f"Метка '{label}': секция = {section}, позиция = {pos}, абсолютный адрес = {hex(abs_addr)}, значение = {value}")

    def tokenize_line(self, line):
        """Посимвольный лексер. Возвращает список токенов: (type, value)"""
        # Удаляем комментарий (всё после ';')
        semi = line.find(';')
        if semi != -1:
            line = line[:semi]
        line = line.rstrip()

        # Если строка пуста — возвращаем пустой список
        if not line:
            return []

        tokens = []
        i = 0
        n = len(line)  # ← ВЫЧИСЛЯЕМ ПОСЛЕ rstrip()!

        while i < n:
            ch = line[i]

            if ch.isspace():
                i += 1
                continue

            # Строка в двойных кавычках
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
                i += 1  # пропустить закрывающую "
                tokens.append(('string', s))
                continue

            # Запятая
            if ch == ',':
                tokens.append(('comma', ','))
                i += 1
                continue

            # Двоеточие
            if ch == ':':
                tokens.append(('colon', ':'))
                i += 1
                continue

            # Слово (идентификатор, число, директива)
            j = i
            while j < n and not (line[j].isspace() or line[j] in ',:;'):
                j += 1
            word = line[i:j]
            if word:
                tokens.append(('word', word))
            i = j

        return tokens


    def parse(self, source):
        lines = source.split('\n')
        self.pass_num = 1
        self.position = {".text": 0, ".data": 0}
        self.sections = {".text": bytearray(), ".data": bytearray()}
        self.log(f"=== PASS {self.pass_num} START ===")
        for line_num, line in enumerate(lines, start=1):
            self.log(f"[PASS {self.pass_num}] Line {line_num}: {line.strip()}")
            try:
                tokens = self.tokenize_line(line)
                self.log_tokens(line_num, tokens)
                self.parse_tokens(tokens)
            except Exception as e:
                self.log(f"ERROR on pass {self.pass_num}, line {line_num}: {str(e)}")
                self.log(traceback.format_exc())
                raise
        self.text_size = self.position[".text"]
        self.data_size = self.position[".data"]

        PAGE_SIZE = 0x1000
        def align_up(x, align):
            return (x + align - 1) & ~(align - 1)
        elf_header_size = 64
        program_header_size = 56
        ph_num = 2
        ph_table_size = program_header_size * ph_num
        self.offset_text = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
        self.offset_data = align_up(self.offset_text + self.text_size, PAGE_SIZE)
        self.vaddr_text = self.code_start
        self.memsz_text = align_up(self.text_size, PAGE_SIZE)
        self.vaddr_data = align_up(self.vaddr_text + self.memsz_text, PAGE_SIZE)
        self.memsz_data = align_up(self.data_size, PAGE_SIZE)
        self.log(f"Calculated addresses:")
        self.log(f".text offset = {hex(self.offset_text)}, vaddr = {hex(self.vaddr_text)}, size = {self.text_size}, memsz = {self.memsz_text}")
        self.log(f".data offset = {hex(self.offset_data)}, vaddr = {hex(self.vaddr_data)}, size = {self.data_size}, memsz = {self.memsz_data}")

        self.pass_num = 3
        self.position = {".text": 0, ".data": 0}
        self.sections = {".text": bytearray(), ".data": bytearray()}
        self.log(f"=== PASS {self.pass_num} START ===")
        for line_num, line in enumerate(lines, start=1):
            self.log(f"[PASS {self.pass_num}] Line {line_num}: {line.strip()}")
            try:
                tokens = self.tokenize_line(line)
                self.parse_tokens(tokens)
            except Exception as e:
                self.log(f"ERROR on pass {self.pass_num}, line {line_num}: {str(e)}")
                self.log(traceback.format_exc())
                raise
        self.log_labels()
        self.verify_addresses()

    def verify_addresses(self):
        self.log("=== Проверка адресов меток ===")
        for label, pos in self.labels.items():
            section = self.label_sections.get(label, "неизвестно")
            base_addr = self.vaddr_text if section == ".text" else self.vaddr_data
            abs_addr = base_addr + pos
            self.log(f"Метка '{label}': секция={section}, позиция={pos}, абсолютный адрес={hex(abs_addr)}")

    def parse_tokens(self, tokens):
        if not tokens:
            return

        # Обработка метки: word colon ...
        if len(tokens) >= 2 and tokens[0][0] == 'word' and tokens[1][0] == 'colon':
            label = tokens[0][1]
            self.labels[label] = self.position[self.current_section]
            self.label_sections[label] = self.current_section
            rest = tokens[2:]
            if rest:
                self.parse_instruction_or_directive(rest)
            return

        # Обработка директив и инструкций
        self.parse_instruction_or_directive(tokens)

    def parse_instruction_or_directive(self, tokens):
        first = tokens[0]
        if first[0] != 'word':
            raise ValueError(f"Ожидалось слово, получено: {first}")

        word = first[1]

        # Директивы
        if word.startswith('.'):
            if word == '.текст':
                self.current_section = ".text"
            elif word == '.данные':
                self.current_section = ".data"
            elif word == '.глобал':
                if len(tokens) < 2 or tokens[1][0] != 'word':
                    raise ValueError(".глобал требует имя метки")
                self.entry_point = tokens[1][1]
            elif word == '.константа':
                if len(tokens) < 3:
                    raise ValueError(".константа требует имя и значение")
                name = tokens[1][1]
                value = self.parse_number_token(tokens[2])
                self.symbols[name] = value
            elif word == '.строка_нуль' or word == '.строка':
                if len(tokens) < 2 or tokens[1][0] != 'string':
                    raise ValueError(f"{word} требует строку в кавычках")
                if self.current_section != ".data":
                    raise ValueError("Строки разрешены только в секции .data")
                s = tokens[1][1]
                bstring = s.encode('utf-8')
                add_null = (word == '.строка_нуль')
                size = len(bstring) + (1 if add_null else 0)
                if self.pass_num == 1:
                    self.position[".data"] += size
                elif self.pass_num == 3:
                    self.sections[".data"] += bstring
                    if add_null:
                        self.sections[".data"] += b'\x00'
                    self.position[".data"] += size
            else:
                raise ValueError(f"Неизвестная директива: {word}")
            return

        # Инструкции
        mnemonic = word
        if mnemonic not in INSTRUCTIONS:
            raise ValueError(f"Неизвестная инструкция: {mnemonic}")

        # Извлекаем операнды: пропускаем запятые
        operands = []
        for tok in tokens[1:]:
            if tok[0] == 'word':
                operands.append(tok[1])
            elif tok[0] == 'comma':
                continue
            else:
                raise ValueError(f"Недопустимый токен в операндах: {tok}")

        if self.pass_num == 3:
            code = self.encode_instruction(mnemonic, operands)
            self.sections[self.current_section] += code
            self.position[self.current_section] += len(code)
        else:
            # Подсчёт размера (как в оригинале)
            instr_info = INSTRUCTIONS[mnemonic]
            if instr_info["type"] == "reg_imm" and len(operands) == 2:
                self.position[self.current_section] += 10
            elif instr_info["type"] in ("reg_reg",) and len(operands) == 2:
                self.position[self.current_section] += 3
            elif instr_info["type"] in ("call", "jmp") and len(operands) == 1:
                self.position[self.current_section] += 5
            elif instr_info["type"] == "jcc" and len(operands) == 1:
                self.position[self.current_section] += 6
            elif instr_info["type"] in ("push", "pop") and len(operands) == 1:
                self.position[self.current_section] += 1
            elif instr_info["type"] == "none" and len(operands) == 0:
                self.position[self.current_section] += len(instr_info["code"])
            else:
                raise ValueError(f"Неподдерживаемые операнды для {mnemonic}: {operands}")

    def parse_number_token(self, token):
        if token[0] != 'word':
            raise ValueError(f"Ожидалось число, получено: {token}")
        s = token[1]
        if s.isdigit():
            return int(s)
        if s.startswith("0x"):
            return int(s, 16)
        raise ValueError(f"Недопустимое число: {s}")

    def encode_instruction(self, mnemonic, operands):
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
            imm = self.parse_operand(operands[1])
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
            target = self.parse_operand(operands[0])
            current_addr = self.vaddr_text + self.position[".text"]  # ИСПРАВЛЕНО!
            offset = target - (current_addr + 5)
            code.extend(struct.pack("<i", offset))
        elif instr["type"] == "jcc" and len(operands) == 1:
            code.extend(instr["code"])
            target = self.parse_operand(operands[0])
            current_addr = self.vaddr_text + self.position[".text"]  # ИСПРАВЛЕНО!
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

    def parse_operand(self, operand):
        if operand.isdigit():
            return int(operand)
        if operand.startswith("0x"):
            return int(operand, 16)
        if operand in self.labels:
            section = self.label_sections[operand]
            base_addr = self.vaddr_text if section == ".text" else self.vaddr_data
            return self.labels[operand] + base_addr
        if operand in self.symbols:
            return self.symbols[operand]
        raise ValueError(f"Неизвестный операнд: {operand}")

    def create_elf(self, filename):
        PAGE_SIZE = 0x1000
        def align_up(x, align):
            return (x + align - 1) & ~(align - 1)
        text = self.sections[".text"]
        data = self.sections[".data"]
        entry_point = self.vaddr_text + self.labels.get(self.entry_point, 0)
        elf_header_size = 64
        program_header_size = 56
        ph_num = 2
        ph_table_size = program_header_size * ph_num
        file_content = bytearray()
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            2,
            0x3E,
            1,
            entry_point,
            elf_header_size,
            0,
            0,
            elf_header_size,
            program_header_size,
            ph_num,
            0,
            0,
            0,
        )
        text_header = struct.pack(
            "<IIQQQQQQ",
            1,
            5,
            self.offset_text,
            self.vaddr_text,
            self.vaddr_text,
            len(text),
            self.memsz_text,
            PAGE_SIZE,
        )
        data_header = struct.pack(
            "<IIQQQQQQ",
            1,
            6,
            self.offset_data,
            self.vaddr_data,
            self.vaddr_data,
            len(data),
            self.memsz_data,
            PAGE_SIZE,
        )
        file_content.extend(elf_header)
        file_content.extend(text_header)
        file_content.extend(data_header)
        if len(file_content) < self.offset_text:
            file_content.extend(b'\x00' * (self.offset_text - len(file_content)))
        file_content.extend(text)
        if len(file_content) < self.offset_data:
            file_content.extend(b'\x00' * (self.offset_data - len(file_content)))
        file_content.extend(data)
        with open(filename, "wb") as f:
            f.write(file_content)
        import os
        os.chmod(filename, 0o755)

if __name__ == "__main__":
    assembler = X64RussianAssembler()
    source = """
    .глобал _start
    .текст
    _start:
        переместить_имм рвх, 1
        переместить_имм рди, 1
        переместить_имм рис, привет_мир
        переместить_имм рдх, длина_строки
        вызов_системы
        переместить_имм рвх, 60
        переместить_имм рди, 0
        вызов_системы
    .данные
    привет_мир:
        .строка "Привет мир!\\n"
    .константа длина_строки 21
    """
    try:
        assembler.parse(source)
        assembler.create_elf("hello.elf")
        assembler.close_log()
        print("ELF-файл успешно создан: hello.elf")
        print("Токены сохранены в tokens.log")
        print("Запустите: ./hello.elf")
    except Exception as e:
        assembler.close_log()
        print(f"Ошибка ассемблирования: {str(e)}")
        sys.exit(1)
