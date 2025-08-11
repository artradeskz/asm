import tkinter as tk
from tkinter import filedialog, messagebox
import os

def binary_to_hex(input_file, output_file=None):
    """Конвертирует бинарный файл в hex-текст"""
    try:
        with open(input_file, 'rb') as bin_file:
            binary_data = bin_file.read()
        
        hex_data = binary_data.hex()
        
        # Форматируем с пробелами между байтами
        formatted_hex = ' '.join([hex_data[i:i+2] for i in range(0, len(hex_data), 2)])
        
        # Если выходной файл не указан, создаём рядом с оригиналом
        if not output_file:
            base_name = os.path.splitext(input_file)[0]
            output_file = f"{base_name}_hex.txt"
        
        with open(output_file, 'w') as hex_file:
            hex_file.write(formatted_hex)
            
        return True, output_file
    
    except Exception as e:
        return False, str(e)

def select_and_convert():
    """Открывает диалог выбора файла и конвертирует"""
    input_file = filedialog.askopenfilename(
        title="Выберите бинарный файл",
        filetypes=(("Бинарные файлы", "*.elf"), ("Все файлы", "*.*"))
    )
    
    if not input_file:
        return
    
    success, result = binary_to_hex(input_file)
    
    if success:
        messagebox.showinfo(
            "Готово",
            f"Файл успешно конвертирован!\nРезультат сохранён как:\n{result}"
        )
    else:
        messagebox.showerror(
            "Ошибка",
            f"Не удалось конвертировать файл:\n{result}"
        )

def main():
    """Создаём графический интерфейс"""
    root = tk.Tk()
    root.title("Бинарный в HEX конвертер")
    root.geometry("400x200")
    
    # Центрируем окно
    root.eval('tk::PlaceWindow . center')
    
    # Создаём элементы интерфейса
    label = tk.Label(
        root,
        text="Конвертер бинарных файлов в HEX-текст",
        font=('Arial', 14),
        pady=20
    )
    label.pack()
    
    btn_convert = tk.Button(
        root,
        text="Выбрать файл и конвертировать",
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