import base64
import hashlib
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import string

# ============================================
# 1) Text Ciphers: Caesar, Vigenère, Playfair
# ============================================

def vigenere_cipher(text, key, encrypt=True):
    result = ""
    key = "".join([c for c in key if c.isalpha()]).lower()
    if not key:
        return "Error: Key must contain at least one letter"
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if not encrypt:
                shift = -shift

            base = ord('A') if char.isupper() else ord('a')
            new_pos = (ord(char) - base + shift) % 26
            result += chr(new_pos + base)
            key_index += 1
        # The original code did not handle non-alpha characters but the logic implies it should.
        # I will keep the original code as is, which only processes alpha characters.
    return result

def caesar_cipher(text, key, encrypt=True):
    result = ""
    if not encrypt:
        key = -key
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + key) % 26 + base)
    return result

def get_valid_integer(prompt):
    while True:
        try:
            value = int(input(prompt))
            return value
        except ValueError:
            print("Invalid input! Please enter an integer number.")

def caesar_menu():
    while True:
        print("\n--- Caesar Cipher ---")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Back to previous menu")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            text = input("Enter the text to encrypt: ")
            key = get_valid_integer("Enter the key (integer): ")
            encrypted = caesar_cipher(text, key, encrypt=True)
            print("\n--- Caesar Cipher Result ---")
            print("Original text:", text)
            print("Encrypted text:", encrypted)
        elif choice == '2':
            text = input("Enter the text to decrypt: ")
            key = get_valid_integer("Enter the key (integer): ")
            decrypted = caesar_cipher(text, key, encrypt=False)
            print("\n--- Caesar Cipher Result ---")
            print("Encrypted text:", text)
            print("Decrypted text:", decrypted)
        elif choice == '3':
            break
        else:
            print("Invalid choice, please try again.")

def vigenere_menu():
    while True:
        print("\n--- Vigenere Cipher ---")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Back to previous menu")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            text = input("Enter the text to encrypt: ")
            key = input("Enter the key (word): ")
            encrypted = vigenere_cipher(text, key, encrypt=True)
            print("\n--- Vigenere Cipher Result ---")
            print("Original text :", text)
            print("Encrypted text:", encrypted)
        elif choice == '2':
            text = input("Enter the text to decrypt: ")
            key = input("Enter the key (word): ")
            decrypted = vigenere_cipher(text, key, encrypt=False)
            print("\n--- Vigenere Cipher Result ---")
            print("Encrypted text :", text)
            print("Decrypted text:", decrypted)
        elif choice == '3':
            break
        else:
            print("Invalid choice, please try again.")

# ---------- Playfair Cipher (Encrypt & Decrypt) ----------

def generate_key_matrix(key):
    key = key.lower().replace("j", "i")
    key = "".join([c for c in key if c.isalpha()])
    seen = set()
    filtered_key = ""
    # Remove duplicates from key
    for c in key:
        if c not in seen:
            filtered_key += c
            seen.add(c)

    # استخدام أبجدية كاملة بدون j
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    # التأكد من أننا نضيف 25 حرفاً فقط
    for c in alphabet:
        if c not in seen and len(seen) < 25:
            filtered_key += c
            seen.add(c)

    # Build 5x5 matrix
    matrix = [list(filtered_key[i:i+5]) for i in range(0, 25, 5)]
    return matrix

def preprocess_text(text):
    # تنظيف النص من الأرقام والرموز
    text = "".join([c.lower() for c in text if c.isalpha()])
    text = text.replace("j", "i")
    print(f"After cleaning: {text}")
    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                result += a + 'x'
                i += 1
            else:
                result += a + b
                i += 2
        else:
            result += a + 'x'
            i += 1

    # التأكد من الطول الزوجي
    if len(result) % 2 != 0:
        result += 'x'
    print(f"After preprocessing: {result}")
    return result

def clean_cipher_input(text):
    # تنظيف النص المشفر
    text = "".join([c.lower() for c in text if c.isalpha()])
    text = text.replace("j", "i")
    if len(text) % 2 != 0:
        text += 'x'
    return text

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return None

def playfair_encrypt(matrix, text):
    result = ""
    print("\nEncryption steps:")
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        ra, ca = find_position(matrix, a)
        rb, cb = find_position(matrix, b)

        if ra == rb:
            enc_a = matrix[ra][(ca + 1) % 5]
            enc_b = matrix[rb][(cb + 1) % 5]
        elif ca == cb:
            enc_a = matrix[(ra + 1) % 5][ca]
            enc_b = matrix[(rb + 1) % 5][cb]
        else:
            enc_a = matrix[ra][cb]
            enc_b = matrix[rb][ca]

        print(f"({a}{b}) -> ({enc_a}{enc_b})")
        result += enc_a + enc_b

    return result

def playfair_decrypt(matrix, text):
    result = ""
    print("\nDecryption steps:")
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        ra, ca = find_position(matrix, a)
        rb, cb = find_position(matrix, b)

        if ra == rb:
            dec_a = matrix[ra][(ca - 1) % 5]
            dec_b = matrix[rb][(cb - 1) % 5]
        elif ca == cb:
            dec_a = matrix[(ra - 1) % 5][ca]
            dec_b = matrix[(rb - 1) % 5][cb]
        else:
            dec_a = matrix[ra][cb]
            dec_b = matrix[rb][ca]

        print(f"({a}{b}) -> ({dec_a}{dec_b})")
        result += dec_a + dec_b

    if result.endswith('x'):
        result = result[:-1]

    return result

def print_matrix(matrix):
    print("\nKey Matrix:")
    for i, row in enumerate(matrix):
        print("{}".format("".join(row)))

def format_preprocessed_text(text):
    return ", ".join([text[i:i+2] for i in range(0, len(text), 2)])

def get_valid_key():
    while True:
        key = input("Enter the key: ")
        clean_key = "".join([c for c in key if c.isalpha()])
        if clean_key:
            return clean_key
        else:
            print("Error: key must contain at least one letter. Please enter again.\n")

def playfair_menu():
    while True:
        print("\n--- Playfair Cipher ---")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Back to previous menu")
        choice = input("Enter your choice (1-3): ")

        if choice == '3':
            print("Returning to previous menu.")
            break
        elif choice in ['1', '2']:
            text = input("Enter the text: ")
            key = get_valid_key()
            matrix = generate_key_matrix(key)
            print_matrix(matrix)

            if choice == '1':
                clean_text = preprocess_text(text)
                formatted_text = format_preprocessed_text(clean_text)
                print(f"\nPreprocessed text: {formatted_text}")
                result = playfair_encrypt(matrix, clean_text)
                print(f"\nEncrypted text: {result.upper()}")
            else:
                clean_text = clean_cipher_input(text)
                formatted_text = format_preprocessed_text(clean_text)
                print(f"\nPreprocessed text: {formatted_text}")
                result = playfair_decrypt(matrix, clean_text)
                print(f"\nDecrypted text: {result}")
        else:
            print("Invalid choice! Please enter 1, 2, or 3.")

def text_ciphers_menu():
    while True:
        print("\n=== Text Encryption (Classical Ciphers) ===")
        print("1. Caesar Cipher")
        print("2. Vigenere Cipher")
        print("3. Playfair Cipher")
        print("4. Back to MAIN MENU")
        choice = input("Enter your choice: ")
        if choice == '1':
            caesar_menu()
        elif choice == '2':
            vigenere_menu()
        elif choice == '3':
            playfair_menu()
        elif choice == '4':
            break
        else:
            print("Invalid choice, please try again.")


# ============================================
# 2) P-Box, S-Box (and their inverses)
# ============================================

def p_box_encrypt(data, p_box):
    if len(data) != len(p_box):
        raise ValueError("Data length must match P-box length.")
    
    data_str = ''.join(str(bit) for bit in data)
    permuted_bits = ['0'] * len(data_str)
    for i, orig_index in enumerate(p_box):
        permuted_bits[i] = data_str[orig_index]
    return ''.join(permuted_bits)

def p_box_decrypt(permuted_data, p_box):
    if len(permuted_data) != len(p_box):
        raise ValueError("Data length must match P-box length.")
    
    original_bits = ['0'] * len(permuted_data)
    for i, orig_index in enumerate(p_box):
        original_bits[orig_index] = permuted_data[i]
    return ''.join(original_bits)

def get_user_input_pbox():
    """Get input data and P-box from user"""
    
    while True:
        try:
            data_input = input("Enter input data as a string of bits (example: 01011): ")
            if all(bit in '01' for bit in data_input) and data_input:
                data = [int(bit) for bit in data_input]
                break
            else:
                print("Error: Data must contain only 0 and 1")
        except ValueError:
            print("Error: Please enter valid integers only")
    
    while True:
        try:
            p_box_input = input(f"Enter P-box as space-separated indices (must have length {len(data)}): ")
            p_box = [int(idx) for idx in p_box_input.split()]
            
            if len(p_box) != len(data):
                print(f"Error: P-box must have {len(data)} elements")
                continue
            
            if all(0 <= idx < len(data) for idx in p_box) and len(set(p_box)) == len(p_box):
                break
            else:
                print(f"Error: Indices must be between 0 and {len(data)-1} and must be unique")
        except ValueError:
            print("Error: Please enter valid integers only")
    
    return data, p_box

def get_user_input_pbox_decrypt():
    """Get input data and P-box for decryption"""
    
    while True:
        try:
            data_input = input("Enter permuted data as a string of bits (example: 11010): ")
            if all(bit in '01' for bit in data_input) and data_input:
                data = data_input
                break
            else:
                print("Error: Data must contain only 0 and 1")
        except ValueError:
            print("Error: Please enter valid bits only")
    
    while True:
        try:
            p_box_input = input(f"Enter P-box as space-separated indices (must have length {len(data)}): ")
            p_box = [int(idx) for idx in p_box_input.split()]
            
            if len(p_box) != len(data):
                print(f"Error: P-box must have {len(data)} elements")
                continue
            
            if all(0 <= idx < len(data) for idx in p_box) and len(set(p_box)) == len(p_box):
                break
            else:
                print(f"Error: Indices must be between 0 and {len(data)-1} and must be unique")
        except ValueError:
            print("Error: Please enter valid integers only")
    
    return data, p_box

S_Box = {
    0: 6,  # 000 -> 110
    1: 1,  # 001 -> 001
    2: 7,  # 010 -> 111
    3: 2,  # 011 -> 010
    4: 3,  # 100 -> 011
    5: 5,  # 101 -> 101
    6: 0,  # 110 -> 000
    7: 4   # 111 -> 100
}

# Inverse S-Box
S_Box_Inverse = {v: k for k, v in S_Box.items()}

def apply_sbox(data):
    if 0 <= data <= 7:
        return S_Box[data]
    else:
        raise ValueError("Input must be a 3-bit integer (0-7).")

def apply_sbox_inverse(data):
    if 0 <= data <= 7:
        return S_Box_Inverse[data]
    else:
        raise ValueError("Input must be a 3-bit integer (0-7).")

def get_user_input_sbox():
    """Get S-box input from user"""
    while True:
        try:
            data_input = input("Enter input for S-box (0-7): ")
            data = int(data_input)
            if 0 <= data <= 7:
                return data
            else:
                print("Error: Input must be between 0 and 7")
        except ValueError:
            print("Error: Please enter an integer between 0 and 7")

def p_box_operation():
    """Handle P-box encryption or decryption"""
    print("\n--- P-box Operation ---")
    print("1. P-box Encryption")
    print("2. P-box Decryption")
    
    while True:
        choice = input("Select operation (1-2): ").strip()
        
        if choice == '1':
            print("\n--- P-box Encryption ---")
            data, p_box = get_user_input_pbox()
            permuted_data = p_box_encrypt(data, p_box)
            print("Original data: ", data)
            print("Permuted data:", permuted_data)
            break
            
        elif choice == '2':
            print("\n--- P-box Decryption ---")
            data, p_box = get_user_input_pbox_decrypt()
            original_data = p_box_decrypt(data, p_box)
            print("Permuted data: ", data)
            print("Original data:", original_data)
            break
            
        else:
            print("Invalid choice! Please select 1 or 2")

def s_box_operation():
    """Handle S-box encryption or decryption"""
    print("\n--- S-box Operation ---")
    print("1. S-box Encryption")
    print("2. S-box Decryption")
    
    while True:
        choice = input("Select operation (1-2): ").strip()
        
        if choice == '1':
            print("\n--- S-box Encryption ---")
            data = get_user_input_sbox()
            output = apply_sbox(data)
            print(f"S-Box input: {data}")
            print(f"S-Box output: {output}")
            break
            
        elif choice == '2':
            print("\n--- S-box Decryption ---")
            data = get_user_input_sbox()
            output = apply_sbox_inverse(data)
            print(f"S-Box input: {data}")
            print(f"S-Box inverse output: {output}")
            break
            
        else:
            print("Invalid choice! Please select 1 or 2")

def pbox_sbox_menu():
    while True:
        print("\n=== Cryptography Operations (P-Box / S-Box) ===")
        print("1. P-box Operations")
        print("2. S-box Operations")
        print("3. Back to MAIN MENU")
        
        choice = input("\nSelect operation (1-3): ").strip()
        
        if choice == '1':
            p_box_operation()
            
        elif choice == '2':
            s_box_operation()
            
        elif choice == '3':
            print("Returning to MAIN MENU.")
            break
            
        else:
            print("Invalid choice! Please select 1-3")


# ============================================
# 3) Create State from Text + ShiftRows
# ============================================

def byte_to_char(b):
    """Convert byte to printable character only."""
    try:
        ch = chr(b)
        # Avoid non-printable chars
        if 32 <= b <= 126:
            return ch
        else:
            return "."
    except:
        return "."

def print_state(title, state):
    print(f"\n{title}")
    for r in range(4):
        row_chars = [byte_to_char(x) for x in state[r]]
        print(row_chars)

def text_to_state_blocks(text: str):
    data = text.encode("utf-8")

    # pad to multiple of 16 bytes
    pad_len = (16 - len(data) % 16) % 16
    if pad_len:
        data += b" " * pad_len

    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    states = []

    print("\n--- Initial State Blocks (as characters) ---")
    for idx, block in enumerate(blocks):
        state = [[0] * 4 for _ in range(4)]
        for i, byte in enumerate(block):
            row = i % 4
            col = i // 4
            state[row][col] = byte

        print(f"\nState #{idx + 1}:")
        print_state("Initial:", state)

        states.append(state)

    return states

def shift_rows(state):
    new_state = [row[:] for row in state]

    for r in range(4):
        row = state[r]
        shift = r
        new_state[r] = row[shift:] + row[:shift]

    print_state("After ShiftRows:", new_state)
    return new_state

def inv_shift_rows(state):
    new_state = [row[:] for row in state]

    for r in range(4):
        row = state[r]
        shift = r
        if shift == 0:
            new_state[r] = row[:]
        else:
            new_state[r] = row[-shift:] + row[:-shift]

    print_state("After Inverse ShiftRows:", new_state)
    return new_state

def state_blocks_to_text(states):
    out_bytes = bytearray()
    for state in states:
        for col in range(4):
            for row in range(4):
                out_bytes.append(state[row][col])
    return out_bytes.decode("utf-8", errors="ignore").rstrip()

def encrypt_shiftrows(plaintext: str) -> str:
    states = text_to_state_blocks(plaintext)
    final_states = []
    for s in states:
        print_state("Before ShiftRows:", s)
        final_states.append(shift_rows(s))
    return state_blocks_to_text(final_states)

def decrypt_shiftrows(ciphertext: str) -> str:
    states = text_to_state_blocks(ciphertext)
    final_states = []
    for s in states:
        print_state("Before Inverse ShiftRows:", s)
        final_states.append(inv_shift_rows(s))
    return state_blocks_to_text(final_states)

def shiftrows_menu():
    print("Choose mode:")
    print(" e = Encrypt (ShiftRows)")
    print(" d = Decrypt (Inverse ShiftRows)")
    mode = input("Mode (e/d): ").strip().lower()

    if mode == "e":
        text = input("Enter plaintext: ")
        result = encrypt_shiftrows(text)
        print("\n=== Ciphertext ===")
        print(result)

    elif mode == "d":
        text = input("Enter ciphertext: ")
        result = decrypt_shiftrows(text)
        print("\n=== Decrypted Text ===")
        print(result)

    else:
        print("Invalid mode. Use 'e' or 'd'.")


# ============================================
# 4) Full DES, AES, RSA (Encrypt / Decrypt)
# ============================================

# ======= Common Helpers =======

def pad(data: bytes, block_size: int) -> bytes:
    """PKCS#7 padding"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes, block_size: int) -> bytes:
    """Remove PKCS#7 padding"""
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def to_bytes(text: str) -> bytes:
    return text.encode("utf-8")

def from_bytes(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def b64decode(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode("ascii"))

# ======= DES (56-bit key, block size 8 bytes) =======

def derive_des_key(key_str: str) -> bytes:
    """
    DES key must be 8 bytes.
    We'll hash the key string and take first 8 bytes.
    """
    h = hashlib.sha256(to_bytes(key_str)).digest()
    return h[:8]

def derive_des_iv(iv_str: str) -> bytes:
    """DES IV is 8 bytes"""
    h = hashlib.sha256(to_bytes(iv_str)).digest()
    return h[:8]

def des_encrypt():
    print("\n=== DES Encryption ===")
    plaintext = input("Enter plaintext: ")
    key_str = input("Enter key (any string): ")
    mode_choice = input("Mode: [1] ECB  [2] CBC (default 1): ").strip() or "1"

    key = derive_des_key(key_str)

    if mode_choice == "2":
        iv_str = input("Enter IV (any string, will be derived to 8 bytes): ")
        iv = derive_des_iv(iv_str)
        cipher = DES.new(key, DES.MODE_CBC, iv)
    else:
        cipher = DES.new(key, DES.MODE_ECB)

    data = pad(to_bytes(plaintext), 8)
    ciphertext = cipher.encrypt(data)
    print("Ciphertext (base64):", b64encode(ciphertext))

def des_decrypt():
    print("\n=== DES Decryption ===")
    ciphertext_b64 = input("Enter ciphertext (base64): ")
    key_str = input("Enter key (same as used for encryption): ")
    mode_choice = input("Mode: [1] ECB  [2] CBC (default 1): ").strip() or "1"

    key = derive_des_key(key_str)

    if mode_choice == "2":
        iv_str = input("Enter IV (same string as used for encryption): ")
        iv = derive_des_iv(iv_str)
        cipher = DES.new(key, DES.MODE_CBC, iv)
    else:
        cipher = DES.new(key, DES.MODE_ECB)

    try:
        ciphertext = b64decode(ciphertext_b64)
        padded_plain = cipher.decrypt(ciphertext)
        plaintext = from_bytes(unpad(padded_plain, 8))
        print("Plaintext:", plaintext)
    except Exception as e:
        print("Decryption failed:", e)

def des_menu():
    while True:
        print("\n=== DES Menu ===")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Back")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            des_encrypt()
        elif choice == "2":
            des_decrypt()
        elif choice == "3":
            break
        else:
            print("Invalid choice")

# ======= AES (128/192/256-bit key, block size 16 bytes) =======

def derive_aes_key(key_str: str, key_bits: int) -> bytes:
    """
    Derive AES key of length key_bits from a passphrase-like string.
    128 -> 16 bytes, 192 -> 24 bytes, 256 -> 32 bytes
    """
    key_len = key_bits // 8
    h = hashlib.sha256(to_bytes(key_str)).digest()
    return h[:key_len]

def derive_aes_iv(iv_str: str) -> bytes:
    """AES IV is 16 bytes"""
    h = hashlib.sha256(to_bytes(iv_str)).digest()
    return h[:16]

def aes_encrypt():
    print("\n=== AES Encryption ===")
    plaintext = input("Enter plaintext: ")
    key_str = input("Enter key (any string): ")
    key_bits_input = input("Key size bits [128/192/256] (default 256): ").strip() or "256"
    try:
        key_bits = int(key_bits_input)
        if key_bits not in (128, 192, 256):
            print("Invalid key size, using 256")
            key_bits = 256
    except ValueError:
        print("Invalid input, using 256")
        key_bits = 256

    mode_choice = input("Mode: [1] ECB  [2] CBC (default 2): ").strip() or "2"

    key = derive_aes_key(key_str, key_bits)

    if mode_choice == "1":
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        iv_str = input("Enter IV (any string, will be derived to 16 bytes): ")
        iv = derive_aes_iv(iv_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)

    data = pad(to_bytes(plaintext), 16)
    ciphertext = cipher.encrypt(data)
    print("Ciphertext (base64):", b64encode(ciphertext))

def aes_decrypt():
    print("\n=== AES Decryption ===")
    ciphertext_b64 = input("Enter ciphertext (base64): ")
    key_str = input("Enter key (same string as used for encryption): ")
    key_bits_input = input("Key size bits [128/192/256] (same as used): ").strip() or "256"
    try:
        key_bits = int(key_bits_input)
        if key_bits not in (128, 192, 256):
            print("Invalid key size, using 256 (might be wrong!)")
            key_bits = 256
    except ValueError:
        print("Invalid input, using 256 (might be wrong!)")
        key_bits = 256

    mode_choice = input("Mode: [1] ECB  [2] CBC (same as used, default 2): ").strip() or "2"

    key = derive_aes_key(key_str, key_bits)

    if mode_choice == "1":
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        iv_str = input("Enter IV (same string as used for encryption): ")
        iv = derive_aes_iv(iv_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        ciphertext = b64decode(ciphertext_b64)
        padded_plain = cipher.decrypt(ciphertext)
        plaintext = from_bytes(unpad(padded_plain, 16))
        print("Plaintext:", plaintext)
    except Exception as e:
        print("Decryption failed:", e)

def aes_menu():
    while True:
        print("\n=== AES Menu ===")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Back")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            aes_encrypt()
        elif choice == "2":
            aes_decrypt()
        elif choice == "3":
            break
        else:
            print("Invalid choice")

# ======= RSA (public-key) =======

current_rsa_key = None  # will hold RSA.RsaKey

def rsa_generate_keys():
    global current_rsa_key
    print("\n=== RSA Key Generation ===")
    bits_input = input("Key size bits [1024/2048/4096] (default 2048): ").strip() or "2048"

    try:
        bits = int(bits_input)
        if bits not in (1024, 2048, 4096):
            print("Invalid key size, using 2048")
            bits = 2048
    except ValueError:
        print("Invalid input, using 2048")
        bits = 2048

    current_rsa_key = RSA.generate(bits)
    private_pem = current_rsa_key.export_key().decode("ascii")
    public_pem = current_rsa_key.publickey().export_key().decode("ascii")

    print("\n--- Private Key (keep secret!) ---")
    print(private_pem)
    print("--- Public Key (share) ---")
    print(public_pem)
    print("Keys stored in memory for this session.")

def rsa_encrypt():
    global current_rsa_key
    print("\n=== RSA Encryption ===")

    if current_rsa_key is None:
        print("No RSA key in memory. Generate one first.")
        return

    public_key = current_rsa_key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)

    plaintext = input("Enter plaintext to encrypt: ")
    plaintext_bytes = to_bytes(plaintext)

    # Note: RSA can only encrypt limited length data; for bigger data, use hybrid crypto.
    try:
        ciphertext = cipher_rsa.encrypt(plaintext_bytes)
        print("Ciphertext (base64):", b64encode(ciphertext))
    except ValueError as e:
        print("Encryption failed (message too long?):", e)

def rsa_decrypt():
    global current_rsa_key
    print("\n=== RSA Decryption ===")

    if current_rsa_key is None:
        print("No RSA private key in memory. Generate one first.")
        return

    cipher_rsa = PKCS1_OAEP.new(current_rsa_key)
    ciphertext_b64 = input("Enter ciphertext (base64): ")

    try:
        ciphertext = b64decode(ciphertext_b64)
        plaintext_bytes = cipher_rsa.decrypt(ciphertext)
        print("Plaintext:", from_bytes(plaintext_bytes))
    except Exception as e:
        print("Decryption failed:", e)

def rsa_menu():
    while True:
        print("\n=== RSA Menu ===")
        print("1) Generate keypair")
        print("2) Encrypt (using in-memory public key)")
        print("3) Decrypt (using in-memory private key)")
        print("4) Back")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            rsa_generate_keys()
        elif choice == "2":
            rsa_encrypt()
        elif choice == "3":
            rsa_decrypt()
        elif choice == "4":
            break
        else:
            print("Invalid choice")

def crypto_primitives_menu():
    print("=== Simple Crypto Tool (DES / AES / RSA) ===")
    while True:
        print("\nMain Crypto Menu:")
        print("1) DES")
        print("2) AES")
        print("3) RSA")
        print("4) Back to MAIN MENU")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            des_menu()
        elif choice == "2":
            aes_menu()
        elif choice == "3":
            rsa_menu()
        elif choice == "4":
            print("Returning to MAIN MENU.")
            break
        else:
            print("Invalid choice, try again.")


# ============================================
# Unified MAIN MENU
# ============================================

def main():
    while True:
        print("\n================= MAIN MENU =================")
        print("1) Text Ciphers (Caesar, Vigenere, Playfair)")
        print("2) P-Box / S-Box Operations")
        print("3) State from Text & ShiftRows Demo")
        print("4) DES / AES / RSA Crypto Tool")
        print("5) Exit")
        print("============================================")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            text_ciphers_menu()
        elif choice == "2":
            pbox_sbox_menu()
        elif choice == "3":
            shiftrows_menu()
        elif choice == "4":
            crypto_primitives_menu()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()