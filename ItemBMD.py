import struct
import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# =============================================================================
# CONSTANTES Y LÓGICA (Mantenida del original)
# =============================================================================

ITEM_SIZE = 708
XOR_KEY = bytes([0xFC, 0xCF, 0xAB])
CRC_WKEY = 0xE2F1

FIELDS = [
    (0, 4, '<I', 'ItemIndex'), (4, 2, '<H', 'ItemSubGroup'), (6, 2, '<H', 'ItemSubIndex'),
    (8, 260, 's', 'szModelFolder'), (268, 260, 's', 'szModelName'), (528, 64, 's', 'szItemName'),
    (592, 1, 'B', 'KindA'), (593, 1, 'B', 'KindB'), (594, 1, 'B', 'Type'), (595, 1, 'B', 'TwoHands'),
    (596, 2, '<H', 'DropLevel'), (598, 1, 'B', 'Slot'), (600, 2, '<H', 'SkillIndex'),
    (602, 1, 'B', 'Width'), (603, 1, 'B', 'Height'), (604, 2, '<H', 'DamageMin'),
    (606, 2, '<H', 'DamageMax'), (608, 1, 'B', 'DefenseRate'), (610, 2, '<H', 'Defense'),
    (612, 2, '<H', 'MagicResistance'), (614, 1, 'B', 'AttackSpeed'), (615, 1, 'B', 'WalkSpeed'),
    (616, 1, 'B', 'Durability'), (617, 1, 'B', 'MagicDur'), (618, 4, '<I', 'MagicPower'),
    (622, 2, '<H', 'ReqStr'), (624, 2, '<H', 'ReqDex'), (626, 2, '<H', 'ReqEne'),
    (628, 2, '<H', 'ReqVit'), (630, 2, '<H', 'ReqCmd'), (632, 2, '<H', 'ReqLvl'),
    (634, 1, 'B', 'ItemValue'), (636, 2, '<H', 'NewReq1'), (638, 2, '<H', 'NewReq2'),
    (640, 2, '<H', 'NewField1'), (642, 2, '<H', 'NewField2'), (644, 2, '<H', 'NewField3'),
    (646, 2, '<H', 'NewField4'), (648, 2, '<H', 'NewField5'), (650, 2, '<H', 'NewField6'),
    (652, 2, '<H', 'NewField7'), (654, 2, '<H', 'NewField8'), (656, 1, 'B', 'NewByte1'),
    (657, 1, 'B', 'DW'), (658, 1, 'B', 'DK'), (659, 1, 'B', 'FE'), (660, 1, 'B', 'MG'),
    (661, 1, 'B', 'DL'), (662, 1, 'B', 'SU'), (663, 1, 'B', 'RF'), (664, 1, 'B', 'GL'),
    (665, 1, 'B', 'RW'), (666, 1, 'B', 'SL'), (667, 1, 'B', 'GC'), (668, 1, 'B', 'Resist1'),
    (669, 1, 'B', 'Resist2'), (670, 1, 'B', 'Resist3'), (671, 1, 'B', 'Resist4'),
    (672, 1, 'B', 'Resist5'), (673, 1, 'B', 'Resist6'), (674, 1, 'B', 'Resist7'),
    (675, 1, 'B', 'Dump'), (676, 1, 'B', 'Transaction'), (677, 1, 'B', 'PersonalStore'),
    (678, 1, 'B', 'Warehouse'), (679, 1, 'B', 'SellNpc'), (680, 1, 'B', 'Expensive'),
    (681, 1, 'B', 'Repair'), (682, 1, 'B', 'Overlap'), (683, 1, 'B', 'PcFlag'),
    (684, 1, 'B', 'MuunFlag'), (685, 1, 'B', 'NewFlag1'), (686, 1, 'B', 'NewFlag2'),
    (687, 1, 'B', 'NewFlag3'), (688, 2, '<H', 'Unk1'), (690, 2, '<H', 'Unk2'),
    (692, 2, '<H', 'Unk3'), (694, 2, '<H', 'Unk4'), (696, 2, '<H', 'Unk5'),
    (698, 2, '<H', 'Unk6'), (700, 2, '<H', 'Unk7'), (702, 2, '<H', 'Unk8'),
    (704, 2, '<H', 'Unk9'), (706, 2, '<H', 'Unk10'),
]

def xor3_crypt(data):
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ XOR_KEY[i % 3]
    return result

def calculate_crc(data):
    crc = CRC_WKEY << 9
    for i in range(0, len(data) - 3, 4):
        temp = struct.unpack('<I', data[i:i+4])[0]
        if (CRC_WKEY + (i >> 2)) % 2 == 1: crc += temp
        else: crc ^= temp
        if i % 16 == 0: crc ^= (crc + CRC_WKEY) >> ((i >> 2) % 8 + 1)
        crc &= 0xFFFFFFFF
    return crc

# =============================================================================
# GUI CLASS
# =============================================================================

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("MU Online S20 Item.bmd Editor")
        self.root.geometry("600x450")
        self.root.resizable(False, False)

        # Estilo
        style = ttk.Style()
        style.configure("TButton", padding=5)
        
        # UI Elements
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="S20 Item.bmd Tool", font=("Helvetica", 16, "bold")).pack(pady=10)
        
        # Frame de acciones
        actions_frame = ttk.LabelFrame(main_frame, text=" Operaciones ", padding="15")
        actions_frame.pack(fill=tk.X, pady=10)

        btn_decode = ttk.Button(actions_frame, text="Decodificar BMD -> TXT", command=self.handle_decode)
        btn_decode.pack(fill=tk.X, pady=5)

        btn_encode = ttk.Button(actions_frame, text="Codificar TXT -> BMD", command=self.handle_encode)
        btn_encode.pack(fill=tk.X, pady=5)

        # Consola de salida
        ttk.Label(main_frame, text="Registro de actividad:").pack(anchor=tk.W)
        self.log_text = tk.Text(main_frame, height=10, state='disabled', background="#f0f0f0")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)

        ttk.Label(main_frame, text="Season 20.2-3 Structure (708 bytes)", font=("Helvetica", 8, "italic")).pack(side=tk.RIGHT)

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        self.root.update()

    def handle_decode(self):
        input_path = filedialog.askopenfilename(title="Seleccionar item.bmd", filetypes=[("BMD files", "*.bmd")])
        if not input_path: return

        output_path = filedialog.asksaveasfilename(title="Guardar como...", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not output_path: return

        try:
            self.log(f"Iniciando decodificación de: {os.path.basename(input_path)}")
            with open(input_path, 'rb') as f:
                data = bytearray(f.read())

            item_count = struct.unpack('<I', data[0:4])[0]
            self.log(f"Items encontrados: {item_count}")

            lines = ['//' + '\t'.join(name for _, _, _, name in FIELDS)]

            for i in range(item_count):
                offset = 4 + (i * ITEM_SIZE)
                decrypted = xor3_crypt(data[offset:offset + ITEM_SIZE])
                
                # Parse item
                item_dict = {}
                for off, size, fmt, name in FIELDS:
                    if fmt == 's':
                        raw = decrypted[off:off + size]
                        item_dict[name] = raw.split(b'\x00')[0].decode('latin-1', errors='replace')
                    else:
                        item_dict[name] = struct.unpack(fmt, decrypted[off:off + size])[0]

                values = [str(item_dict[name]) for _, _, _, name in FIELDS]
                lines.append('\t'.join(values))
                
                if (i + 1) % 500 == 0: self.log(f"Procesando... {i+1}/{item_count}")

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))

            self.log("¡Éxito! Archivo TXT generado.")
            messagebox.showinfo("Completado", "Decodificación exitosa.")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Ocurrió un error: {e}")

    def handle_encode(self):
        input_path = filedialog.askopenfilename(title="Seleccionar item.txt", filetypes=[("Text files", "*.txt")])
        if not input_path: return

        output_path = filedialog.asksaveasfilename(title="Guardar como...", defaultextension=".bmd", filetypes=[("BMD files", "*.bmd")])
        if not output_path: return

        try:
            self.log(f"Iniciando codificación de: {os.path.basename(input_path)}")
            field_names = [name for _, _, _, name in FIELDS]
            
            with open(input_path, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith('//')]

            self.log(f"Items a procesar: {len(lines)}")
            items_data = bytearray()

            for i, line in enumerate(lines):
                parts = line.split('\t')
                item_dict = {name: parts[j] if j < len(parts) else '' for j, name in enumerate(field_names)}
                
                # Build item binary
                item_bin = bytearray(ITEM_SIZE)
                for offset, size, fmt, name in FIELDS:
                    val = item_dict.get(name, '' if fmt == 's' else 0)
                    if fmt == 's':
                        encoded = str(val).encode('latin-1', errors='replace')[:size-1]
                        item_bin[offset:offset + len(encoded)] = encoded
                    else:
                        item_bin[offset:offset + size] = struct.pack(fmt, int(val) if val else 0)
                
                items_data.extend(item_bin)
                if (i + 1) % 500 == 0: self.log(f"Cifrando... {i+1}/{len(lines)}")

            encrypted = xor3_crypt(items_data)
            crc = calculate_crc(bytes(encrypted))

            output = bytearray()
            output.extend(struct.pack('<I', len(lines)))
            output.extend(encrypted)
            output.extend(struct.pack('<I', crc))

            with open(output_path, 'wb') as f:
                f.write(output)

            self.log(f"¡Éxito! Archivo BMD generado ({len(output)} bytes).")
            messagebox.showinfo("Completado", "Codificación exitosa.")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", f"Ocurrió un error: {e}")

if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()