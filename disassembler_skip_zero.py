import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess

def binary_to_disasm(input_file, output_file=None):
    """Конвертирует бинарный файл в дизассемблированный код с помощью ndisasm, исключая строки с 'add [rax],al'."""
    try:
        # Если выходной файл не указан, создаём рядом с оригиналом
        if not output_file:
            base_name = os.path.splitext(input_file)[0]
            output_file = f"{base_name}_disasm.txt"
        
        # Вызываем ndisasm для дизассемблирования
        result = subprocess.run(
            ['ndisasm', '-b64', input_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Проверяем наличие ошибок от ndisasm
        if result.returncode != 0:
            error_msg = result.stderr.strip()
            return False, f"Ошибка ndisasm: {error_msg}"

        # Фильтруем строки: исключаем те, которые содержат 'add [rax],al'
        # Разбиваем вывод на строки
        lines = result.stdout.splitlines()
        # Фильтруем, исключая строки с 'add [rax],al'
        # Используем strip(), чтобы убрать лишние пробелы/переводы строк, если нужно
        filtered_lines = [line for line in lines if 'add [rax],al' not in line]

        # Записываем отфильтрованные строки в файл
        with open(output_file, 'w', encoding='utf-8') as out_file:
            for line in filtered_lines:
                out_file.write(line + '\n') # Восстанавливаем перевод строки
        
        return True, output_file
    
    except FileNotFoundError:
        return False, "ndisasm не найден. Убедитесь, что NASM установлен и доступен в PATH"
    except Exception as e:
        return False, str(e)

def select_and_convert():
    """Открывает диалог выбора файла и конвертирует"""
    input_file = filedialog.askopenfilename(
        title="Выберите бинарный файл",
        filetypes=(("Бинарные файлы", "*.bin *.elf *.o"), ("Все файлы", "*.*")) # Расширим типы файлов
    )
    
    if not input_file:
        return
    
    success, result = binary_to_disasm(input_file)
    
    if success:
        messagebox.showinfo(
            "Готово",
            f"Файл успешно дизассемблирован!\nНули (add [rax],al) удалены.\nРезультат сохранён как:\n{result}"
        )
    else:
        messagebox.showerror(
            "Ошибка",
            f"Не удалось дизассемблировать файл:\n{result}"
        )

def main():
    """Создаём графический интерфейс"""
    root = tk.Tk()
    root.title("Дизассемблер бинарных файлов")
    root.geometry("450x200")
    
    # Центрируем окно
    root.eval('tk::PlaceWindow . center')
    
    # Создаём элементы интерфейса
    label = tk.Label(
        root,
        text="Дизассемблер бинарных файлов (ndisasm)",
        font=('Arial', 14),
        pady=20
    )
    label.pack()
    
    btn_convert = tk.Button(
        root,
        text="Выбрать файл и дизассемблировать",
        command=select_and_convert,
        font=('Arial', 12),
        padx=20,
        pady=10
    )
    btn_convert.pack()
    
    btn_exit = tk.Button(
        root,
        text="Выход",
        command=root.quit,
        font=('Arial', 10),
        padx=20,
        pady=5
    )
    btn_exit.pack(pady=20)
    
    root.mainloop()

if __name__ == "__main__":
    main()
