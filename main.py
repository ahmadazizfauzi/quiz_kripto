# INSTALL GRADLE
!pip install gradio

# IMPORT LIBRARY
import gradio as gr
import numpy as np
from sympy import Matrix

# READ TXT
def read_file(file):
    if file is None:
        return ""
    with open(file.name, "r", encoding="utf-8") as f:
        return f.read()


# ----------------- Vigenere Cipher -----------------
def vigenere_encrypt(message, key):
    encrypted_message = []
    # key tanpa spasi
    key = key.lower().replace(" ", "")  
    key_length = len(key)
    key_index = 0  

    for char in message:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('a')
            if char.isupper():
                encrypted_message.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                encrypted_message.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            key_index += 1  
        else:
            encrypted_message.append(char)  

    return ''.join(encrypted_message)


def vigenere_decrypt(encrypted_message, key):
    decrypted_message = []
    key = key.lower().replace(" ", "")  
    key_length = len(key)
    key_index = 0  

    for char in encrypted_message:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('a')
            if char.isupper():
                decrypted_message.append(chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A')))
            else:
                decrypted_message.append(chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a')))
            key_index += 1  
        else:
            decrypted_message.append(char)  

    return ''.join(decrypted_message)



# ----------------- playfair Cipher -----------------
def generate_playfair_matrix(key):
    matrix = []
    key = key.lower().replace('j', 'i')  # Ganti 'j' dengan 'i'
    key = ''.join(sorted(set(key), key=key.index))  
    alphabet = 'abcdefghiklmnopqrstuvwxyz'  
    used = set()

    for char in key:
        if char not in used and char != 'j':
            matrix.append(char)
            used.add(char)

    for char in alphabet:
        if char not in used:
            matrix.append(char)
            used.add(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return None

def playfair_encrypt(message, key):
    message = message.lower().replace('j', 'i')
    
    # Simpan posisi spasi
    spaces = [pos for pos, char in enumerate(message) if char == ' ']
    message = message.replace(' ', '')  

    matrix = generate_playfair_matrix(key)
    digraphs = []
    encrypted_message = []

    # Create digraphs (pairs of letters)
    i = 0
    while i < len(message):
        if i + 1 < len(message) and message[i] != message[i + 1]:
            digraphs.append((message[i], message[i + 1]))
            i += 2
        else:
            digraphs.append((message[i], 'x'))  
            i += 1

    for digraph in digraphs:
        row1, col1 = find_position(matrix, digraph[0])
        row2, col2 = find_position(matrix, digraph[1])

        if row1 == row2:
            # Same row: Shift right
            encrypted_message.append(matrix[row1][(col1 + 1) % 5])
            encrypted_message.append(matrix[row2][(col2 + 1) % 5])
        elif col1 == col2:
            # Same column: Shift down
            encrypted_message.append(matrix[(row1 + 1) % 5][col1])
            encrypted_message.append(matrix[(row2 + 1) % 5][col2])
        else:
            # Rectangle swap
            encrypted_message.append(matrix[row1][col2])
            encrypted_message.append(matrix[row2][col1])

    # Ubah menjadi huruf besar dan gabungkan hasil tanpa spasi
    encrypted_message = ''.join(encrypted_message).upper()

    return encrypted_message

def playfair_decrypt(encrypted_message, key):
  
    spaces = [pos for pos, char in enumerate(encrypted_message) if char == ' ']
    encrypted_message = encrypted_message.replace(' ', '')  

    matrix = generate_playfair_matrix(key)
    digraphs = [(encrypted_message[i], encrypted_message[i + 1]) for i in range(0, len(encrypted_message), 2)]
    decrypted_message = []

    for digraph in digraphs:
        row1, col1 = find_position(matrix, digraph[0].lower())
        row2, col2 = find_position(matrix, digraph[1].lower())

        if row1 == row2:
            # Same row: Shift left
            decrypted_message.append(matrix[row1][(col1 - 1) % 5])
            decrypted_message.append(matrix[row2][(col2 - 1) % 5])
        elif col1 == col2:
            # Same column: Shift up
            decrypted_message.append(matrix[(row1 - 1) % 5][col1])
            decrypted_message.append(matrix[(row2 - 1) % 5][col2])
        else:
            # Rectangle swap
            decrypted_message.append(matrix[row1][col2])
            decrypted_message.append(matrix[row2][col1])

    decrypted_message = ''.join(decrypted_message)

    # Menghapus huruf 'x' yang ditambahkan untuk pasangan, kecuali jika 'x' benar-benar bagian dari pesan asli
    decrypted_message = decrypted_message.rstrip('x')

    # Tambahkan kembali spasi pada posisi semula
    for pos in spaces:
        decrypted_message = decrypted_message[:pos] + ' ' + decrypted_message[pos:]

    return decrypted_message




# Hill Chiper
# ----------------- Hill Cipher -----------------
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def hill_encrypt(plaintext, key):
    # Pastikan kunci hanya berisi huruf dan memiliki panjang 16 karakter
    key = ''.join(filter(str.isalpha, key.lower()))
    if len(key) != 16:
        return "Error: Kunci harus terdiri dari 16 huruf untuk matriks 4x4."
    
    key_matrix = np.array([ord(c) - ord('a') for c in key]).reshape(4, 4)
    
    # Hitung determinan dan pastikan invertibel modulo 26
    det = int(round(np.linalg.det(key_matrix))) % 26
    if det == 0 or gcd(det, 26) != 1:
        return "Error: Determinan matriks kunci tidak invertibel modulo 26. Pilih kunci lain."
    
    # Hapus karakter non-alfabet dan ubah menjadi lowercase
    plaintext = ''.join(filter(str.isalpha, plaintext.lower()))
    
    # Padding jika panjang plaintext tidak kelipatan 4
    if len(plaintext) % 4 != 0:
        padding = 4 - (len(plaintext) % 4)
        plaintext += 'x' * padding
    
    ciphertext = ''
    
    for i in range(0, len(plaintext), 4):
        block = plaintext[i:i+4]
        block_vector = np.array([ord(c) - ord('a') for c in block])
        encrypted_vector = (block_vector @ key_matrix) % 26
        ciphertext += ''.join([chr(num + ord('a')) for num in encrypted_vector])
    
    return ciphertext

def hill_decrypt(ciphertext, key):
    # Pastikan kunci hanya berisi huruf dan memiliki panjang 16 karakter
    key = ''.join(filter(str.isalpha, key.lower()))
    if len(key) != 16:
        return "Error: Kunci harus terdiri dari 16 huruf untuk matriks 4x4."
    
    key_matrix = np.array([ord(c) - ord('a') for c in key]).reshape(4, 4)
    
    # Hitung determinan dan pastikan invertibel modulo 26
    det = int(round(np.linalg.det(key_matrix))) % 26
    if det == 0 or gcd(det, 26) != 1:
        return "Error: Determinan matriks kunci tidak invertibel modulo 26. Pilih kunci lain."
    
    try:
        det_inv = pow(det, -1, 26)
    except ValueError:
        return "Error: Determinan matriks kunci tidak invertibel modulo 26. Pilih kunci lain."
    
    adjugate_matrix = np.array([[ key_matrix[1,1], -key_matrix[0,1], key_matrix[0,2], key_matrix[0,3]],
                                [-key_matrix[1,0], key_matrix[0,0], -key_matrix[0,2], -key_matrix[0,3]],
                                [ key_matrix[2,1], -key_matrix[1,1], key_matrix[1,2], key_matrix[1,3]],
                                [-key_matrix[2,0], key_matrix[1,0], -key_matrix[1,2], -key_matrix[1,3]]]) % 26
    inverse_key_matrix = (det_inv * adjugate_matrix) % 26
    
    # Hapus karakter non-alfabet dan ubah menjadi lowercase
    ciphertext = ''.join(filter(str.isalpha, ciphertext.lower()))
    
    if len(ciphertext) % 4 != 0:
        return "Error: Panjang ciphertext harus kelipatan 4."
    
    plaintext = ''
    
    for i in range(0, len(ciphertext), 4):
        block = ciphertext[i:i+4]
        block_vector = np.array([ord(c) - ord('a') for c in block])
        decrypted_vector = (block_vector @ inverse_key_matrix) % 26
        plaintext += ''.join([chr(int(num) + ord('a')) for num in decrypted_vector])
    
    return plaintext




#  Gradio
# ----------------- Gradio Interface -----------------

def process_text(file, message, key, mode, algorithm):
    if file:
        message = read_file(file)

    if len(key) < 12:
        return "Kunci harus minimal 12 karakter!"
    
    if algorithm == "Vigenere Cipher":
        if mode == "Encrypt":
            return vigenere_encrypt(message, key)
        else:
            return vigenere_decrypt(message, key)
    
    elif algorithm == "Playfair Cipher":
        if mode == "Encrypt":
            return playfair_encrypt(message, key)
        else:
            return playfair_decrypt(message, key)
    
    elif algorithm == "Hill Cipher":
        if mode == "Encrypt":
            return hill_encrypt(message, key)
        else:
            return hill_decrypt(message, key)
    
    return "Algoritma tidak dikenali"

# Antarmuka Gradio yang diperbarui
with gr.Blocks() as demo:
    gr.Markdown("# Cipher Program")
    
    # Komponen untuk mengunggah file .txt
    file_input = gr.File(label="Unggah file .txt (opsional)", file_types=["text"])

    # Komponen untuk input manual pesan
    message = gr.Textbox(label="Atau masukkan pesan secara manual", placeholder="Jika tanpa file, input pesan ")

    # Komponen untuk input kunci
    key = gr.Textbox(label="Masukkan kunci (minimal 12 karakter)", placeholder="Input kunci")

    # Komponen untuk memilih mode enkripsi atau dekripsi
    mode = gr.Radio(choices=["Encrypt", "Decrypt"], label="Mode")
    
    # Komponen untuk memilih algoritma
    algorithm = gr.Dropdown(choices=["Vigenere Cipher", "Playfair Cipher", "Hill Cipher"], label=" Algoritma")

    # Komponen untuk menampilkan hasil
    output = gr.Textbox(label="Hasil")

    # Tombol untuk memproses
    submit_button = gr.Button("Proses")

    # Menghubungkan tombol dengan fungsi pemrosesan
    submit_button.click(process_text, inputs=[file_input, message, key, mode, algorithm], outputs=output)

    