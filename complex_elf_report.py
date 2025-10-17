import r2pipe
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess

class FullDumpWithNDISASM:
    def __init__(self, binary_path):
        self.r2 = r2pipe.open(binary_path, flags=[
            '-e', 'bin.relocs.apply=true',
            '-e', 'io.cache=true'
        ])
        self.binary_path = binary_path
        self.file_size = os.path.getsize(binary_path)

    def _get_readelf_segments(self):
        """Получить информацию о сегментах через readelf -l"""
        try:
            result = subprocess.run(
                ['readelf', '-l', self.binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Ошибка readelf:\n{e.stderr}"
        except FileNotFoundError:
            return "ОШИБКА: readelf не найден. Установите: sudo apt install binutils"
        except Exception as e:
            return f"Ошибка readelf: {str(e)}"

    def _run_ndisasm_full(self):
        try:
            info = self.r2.cmdj('ij')
            bits = info.get('bin', {}).get('bits', 64)
            arch_flag = '-b64' if bits == 64 else '-b32'

            result = subprocess.run(
                ['ndisasm', arch_flag, self.binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Ошибка ndisasm:\n{e.stderr}"
        except FileNotFoundError:
            return "ОШИБКА: ndisasm не найден. Установите: sudo apt install nasm"
        except Exception as e:
            return f"Ошибка ndisasm: {str(e)}"

    def save_full_report(self, output_path):
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # === ВВЕДЕНИЕ ДЛЯ НЕЙРОСЕТИ ===
                f.write("# АНАЛИЗ ELF-ФАЙЛА ДЛЯ ИИ\n")
                f.write("=" * 80 + "\n")
                f.write("Этот отчёт состоит из трёх частей:\n")
                f.write("1. СЕГМЕНТЫ ELF — выполнен с помощью readelf -l\n")
                f.write("2. СТРУКТУРНЫЙ АНАЛИЗ — выполнен с помощью Radare2 (r2pipe).\n")
                f.write("   Включает: заголовок ELF, секции, сегменты, hex-дамп(именно содержимое файла на диске).\n")
                f.write("3. ДИЗАССЕМБЛЕР — выполнен с помощью ndisasm (из пакета NASM).\n")
                f.write("   ВАЖНО: ndisasm интерпретирует ВЕСЬ файл как raw x86/x64 машинный код,\n")
                f.write("   включая ELF-заголовок, таблицы символов и данные. Это может привести\n")
                f.write("   к появлению 'мусорных' инструкций (например, 'add [rax], al').\n")
                f.write("   Такое поведение НОРМАЛЬНО и ожидаемо для ndisasm.\n")
                f.write("=" * 80 + "\n\n")

                # === 1. СЕГМЕНТЫ ELF (READELF) ===
                f.write("# 1. СЕГМЕНТЫ ELF (команда: readelf -l)\n")
                f.write("=" * 80 + "\n")
                f.write("Команда: readelf -l {имя_файла}\n")
                f.write("Эта команда показывает програмные заголовки (сегменты) ELF файла,\n")
                f.write("включая информацию о том, какие части файла загружаются в память,\n")
                f.write("разрешения сегментов (R/W/X) и их выравнивание.\n")
                f.write("-" * 40 + "\n")
                
                readelf_output = self._get_readelf_segments()
                f.write(readelf_output if readelf_output.strip() else "Нет данных о сегментах\n")
                f.write("\n" + "=" * 80 + "\n\n")

                # === 2. СТРУКТУРНЫЙ АНАЛИЗ (RADARE2) ===
                f.write("# 2. СТРУКТУРНЫЙ АНАЛИЗ (через Radare2 / r2pipe)\n")
                f.write("=" * 80 + "\n")

                # ELF Header
                f.write("\n## ELF HEADER (команда: iH)\n")
                f.write("-" * 40 + "\n")
                header = self.r2.cmd('iH')
                f.write(header if header.strip() else "Нет данных\n")

                # Sections
                f.write("\n## SECTIONS (команда: iS)\n")
                f.write("-" * 40 + "\n")
                sections_out = self.r2.cmd('iS')
                f.write(sections_out if sections_out.strip() else "Нет секций\n")

                # Segments
                f.write("\n## PROGRAM HEADERS / MEMORY MAP (команда: iM)\n")
                f.write("-" * 40 + "\n")
                segments_out = self.r2.cmd('iM')
                f.write(segments_out if segments_out.strip() else "Нет сегментов\n")

                # Hex Dump
                f.write(f"\n## FULL HEX DUMP (весь файл, {self.file_size} байт)\n")
                f.write("-" * 40 + "\n")
                f.write("Команда: px <размер> @ 0\n")
                hex_full = self.r2.cmd(f'px {self.file_size} @ 0')
                f.write(hex_full if hex_full.strip() else "Не удалось прочитать\n")

                # === 3. ДИЗАССЕМБЛЕР (NDISASM) ===
                f.write("\n\n# 3. ДИЗАССЕМБЛЕР (через ndisasm)\n")
                f.write("=" * 80 + "\n")
                f.write("Инструмент: ndisasm (часть пакета NASM)\n")
                f.write("Режим: raw binary → x86/x64 assembly\n")
                f.write("Особенности:\n")
                f.write("- Входные данные: ВЕСЬ бинарный файл целиком (включая заголовки и данные)\n")
                f.write("- Нет знания о формате ELF — интерпретация как сплошной поток инструкций\n")
                f.write("- Инструкции из не-кодовых областей (например, ELF magic 0x7F454C46)\n")
                f.write("  будут декодированы как 'add [rax], al' и подобные 'мусорные' команды.\n")
                f.write("- Это НЕ ошибка — так работает линейный дизассемблер ndisasm.\n")
                f.write("- Для точного анализа кодовых секций используйте информацию из раздела 'SECTIONS'.\n")
                f.write("- Адреса в ndisasm начинаются с 0x00000000 (виртуальная адресация не учитывается).\n")
                f.write("\n## ПОЛНЫЙ ДИЗАССЕМБЛЕРНЫЙ ЛИСТИНГ (ndisasm)\n")
                f.write("-" * 40 + "\n")
                ndisasm_output = self._run_ndisasm_full()
                f.write(ndisasm_output)

            self.r2.quit()

        except Exception as e:
            self.r2.quit()
            raise e


class FullDumpGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ELF-анализ для нейросети")
        self.root.geometry("880x520")

        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = tk.Label(
            main_frame,
            text="Генерация отчёта ELF для анализа нейросетью",
            font=("Arial", 13, "bold"),
            pady=10
        )
        title_label.pack()

        note_label = tk.Label(
            main_frame,
            text="✅ Сегменты ELF — через readelf -l\n"
                 "✅ Структурные данные — через Radare2\n"
                 "✅ Дизассемблер — через ndisasm (весь файл как raw-код, без фильтрации)\n"
                 "ℹ️ Отчёт содержит пояснения для ИИ",
            fg="purple",
            justify=tk.LEFT
        )
        note_label.pack(anchor=tk.W, pady=(0, 15))

        self.select_btn = tk.Button(
            main_frame,
            text="Выбрать ELF-файл",
            command=self.analyze_file,
            font=("Arial", 12),
            bg="#673AB7",
            fg="white",
            padx=20,
            pady=10
        )
        self.select_btn.pack(pady=10)

        self.status_var = tk.StringVar()
        self.status_var.set("Готов. Требуется: readelf, radare2 и nasm")
        status_bar = tk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def analyze_file(self):
        file_path = filedialog.askopenfilename(
            title="Выберите ELF-файл",
            filetypes=[
                ("ELF", "*.so *.o *.a"),
                ("Исполняемые", "*"),
                ("Все файлы", "*.*")
            ]
        )
        if not file_path:
            return

        try:
            self.status_var.set("Генерация отчёта для ИИ...")
            self.select_btn.config(state=tk.DISABLED)
            self.root.update()

            base = os.path.splitext(file_path)[0]
            output_file = f"{base}_AI_REPORT.txt"

            inspector = FullDumpWithNDISASM(file_path)
            inspector.save_full_report(output_file)

            self.status_var.set(f"✅ Готово! Отчёт: {os.path.basename(output_file)}")
            messagebox.showinfo("Успех", f"Отчёт для нейросети создан:\n{output_file}")

        except Exception as e:
            self.status_var.set("❌ Ошибка!")
            messagebox.showerror("Ошибка", f"Не удалось создать отчёт:\n{str(e)}")
        finally:
            self.select_btn.config(state=tk.NORMAL)


if __name__ == "__main__":
    root = tk.Tk()
    app = FullDumpGUI(root)
    root.mainloop()
