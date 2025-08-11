import re
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
        self.sections = {
            ".text": bytearray(),
            ".data": bytearray(),
        }
        self.current_section = ".text"
        self.entry_point = "_start"
        self.position = {".text": 0, ".data": 0}
        self.pass_num = 0
        self.code_start = 0x400000
        self.log_file = open("asm_log.txt", "w", encoding="utf-8")

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

    def close_log(self):
        self.log_file.close()

    def log_labels(self):
        self.log("=== Метки и их адреса ===")
        for label, pos in self.labels.items():
            section = self.label_sections.get(label, "неизвестно")
            base_addr = self.vaddr_text if section == ".text" else self.vaddr_data
            abs_addr = base_addr + pos
            value = self.symbols.get(label, "N/A")
            self.log(f"Метка '{label}': секция = {section}, позиция = {pos}, абсолютный адрес = {hex(abs_addr)}, значение = {value}")

    def parse(self, source):
        lines = source.split('\n')

        # Первый проход: сбор меток и подсчёт размеров
        self.pass_num = 1
        self.position = {".text": 0, ".data": 0}
        self.sections = {".text": bytearray(), ".data": bytearray()}
        self.log(f"=== PASS {self.pass_num} START ===")
        for line_num, line in enumerate(lines, start=1):
            self.log(f"[PASS {self.pass_num}] Line {line_num}: {line.strip()}")
            try:
                self.parse_line(line)
            except Exception as e:
                self.log(f"ERROR on pass {self.pass_num}, line {line_num}: {str(e)}")
                self.log(traceback.format_exc())
                raise

        self.text_size = self.position[".text"]
        self.data_size = self.position[".data"]

        # Второй проход: вычисление адресов и выравнивание
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

        # Третий проход: генерация кода и проверка
        self.pass_num = 3
        self.position = {".text": 0, ".data": 0}
        self.sections = {".text": bytearray(), ".data": bytearray()}
        self.log(f"=== PASS {self.pass_num} START ===")
        for line_num, line in enumerate(lines, start=1):
            self.log(f"[PASS {self.pass_num}] Line {line_num}: {line.strip()}")
            try:
                self.parse_line(line)
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
        # Здесь можно добавить дополнительные проверки по необходимости

    def parse_line(self, line):
        line = re.sub(r';.*$', '', line).strip()
        if not line:
            return

        if line.startswith('.'):
            parts = line.split()
            directive = parts[0]

            if directive == '.раздел':
                self.current_section = parts[1]
            elif directive == '.глобал':
                self.entry_point = parts[1]
            elif directive == '.константа':
                self.symbols[parts[1]] = int(parts[2], 0)
            elif directive == '.текст':
                self.current_section = ".text"
            elif directive == '.данные':
                self.current_section = ".data"
            elif directive == '.строка_нуль':
                if self.current_section != ".data":
                    raise ValueError("Строки разрешены только в секции .data")
                string = ' '.join(parts[1:])
                string = string.strip('"')
                bstring = string.encode('utf-8')
                if self.pass_num == 1:
                    self.position[".data"] += len(bstring) + 1
                elif self.pass_num == 3:
                    self.sections[".data"] += bstring + b'\x00'
                    self.position[".data"] += len(bstring) + 1
            return

        if ':' in line:
            label, rest = line.split(':', 1)
            label = label.strip()
            self.labels[label] = self.position[self.current_section]
            self.label_sections[label] = self.current_section
            if not rest.strip():
                return
            line = rest.strip()

        tokens = re.split(r'[,\s]+', line)
        tokens = [t for t in tokens if t]
        if not tokens:
            return

        mnemonic = tokens[0]
        if mnemonic not in INSTRUCTIONS:
            raise ValueError(f"Неизвестная инструкция: {mnemonic}")

        operands = tokens[1:]

        if self.pass_num == 3:
            code = self.encode_instruction(mnemonic, operands)
            self.sections[self.current_section] += code
            self.position[self.current_section] += len(code)
        else:
            if mnemonic == "переместить_имм" and len(operands) == 2:
                # размер инструкции: 10 байт (REX + opcode + 8 байт imm)
                self.position[self.current_section] += 10
            elif mnemonic in ["переместить", "прибавить", "вычесть", "сравнить"] and len(operands) == 2:
                # размер инструкции: 3 байта (opcode(2) + modrm)
                self.position[self.current_section] += 3
            elif mnemonic in ["вызвать", "переход"] and len(operands) == 1:
                # размер инструкции: 5 байт (opcode + rel32)
                self.position[self.current_section] += 5
            elif mnemonic in ["переход_если_равно", "переход_если_неравно"] and len(operands) == 1:
                # размер инструкции: 6 байт (two-byte opcode + rel32)
                self.position[self.current_section] += 6
            elif mnemonic in ["втолкнуть", "вытолкнуть"] and len(operands) == 1:
                # push/pop рвх (рвх == рег 0) — 1 байт
                self.position[self.current_section] += 1
            elif mnemonic in ["вернуться", "вызов_системы", "нет_операции", "остановить"] and len(operands) == 0:
                # 1-2 байта
                self.position[self.current_section] += len(INSTRUCTIONS[mnemonic]["code"])
            else:
                raise ValueError(f"Неподдерживаемые операнды для {mnemonic}: {operands}")

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

        elif instr["type"] == "call" and len(operands) == 1:
            code.extend(instr["code"])
            target = self.parse_operand(operands[0])
            current_pos = self.vaddr_text + self.position[".text"] + len(self.sections[".text"])
            offset = target - (current_pos + 5)
            code.extend(struct.pack("<i", offset))

        elif instr["type"] == "jmp" and len(operands) == 1:
            code.extend(instr["code"])
            target = self.parse_operand(operands[0])
            current_pos = self.vaddr_text + self.position[".text"] + len(self.sections[".text"])
            offset = target - (current_pos + 5)
            code.extend(struct.pack("<i", offset))

        elif instr["type"] == "jcc" and len(operands) == 1:
            code.extend(instr["code"])
            target = self.parse_operand(operands[0])
            current_pos = self.vaddr_text + self.position[".text"] + len(self.sections[".text"])
            offset = target - (current_pos + 6)
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
        if isinstance(operand, list):
            raise ValueError("Ожидался одиночный операнд, получен список")
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

        # Используем вычисленные offset и размеры
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
        переместить_имм рвх, 1          ; syscall write
        переместить_имм рди, 1          ; stdout
        переместить_имм рис, привет_мир ; адрес буфера с текстом
        переместить_имм рдх, длина_строки ; длина строки
        вызов_системы                   ; вызов write

        переместить_имм рвх, 60         ; syscall exit
        переместить_имм рди, 0          ; код возврата 0
        вызов_системы                   ; вызов exit

    .данные
    привет_мир:
        .строка_нуль "Привет мир!"
    .длина_строки:
        .константа длина_строки 21
    """


    try:
        assembler.parse(source)
        assembler.create_elf("hello.elf")
        assembler.close_log()
        print("ELF-файл успешно создан: hello.elf")
        print("Запустите: ./hello.elf")
    except Exception as e:
        assembler.close_log()
        print(f"Ошибка ассемблирования: {str(e)}")
        sys.exit(1)
