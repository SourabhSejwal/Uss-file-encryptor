from tkinter import *
from tkinter import filedialog, ttk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os
import time
from Crypto.Hash import SHA256
class DecryptionError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

SHA_DIGEST_SIZE = SHA256.digest_size
def encrypt_message_text(a_message, publickey):
    cipher = PKCS1_OAEP.new(publickey)
    encrypted_msg = cipher.encrypt(a_message.encode())
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

def decrypt_message_text(encoded_encrypted_msg, privatekey):
    cipher = PKCS1_OAEP.new(privatekey)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = cipher.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg.decode()

# def generate_keys_clicked():
#     privatekey, publickey = generate_keys(rsa_length)
#     private_key_text.delete('1.0', END)
#     private_key_text.insert(END, privatekey.export_key().decode())
#     public_key_text.delete('1.0', END)
#     public_key_text.insert(END, publickey.export_key().decode())

def encrypt_clicked_text():
    a_message = input_text.get('1.0', END)
    publickey_str = public_key_text.get('1.0', END)
    publickey = RSA.import_key(publickey_str)
    encrypted_msg = encrypt_message_text(a_message, publickey)
    output_text.delete('1.0', END)
    output_text.insert(END, encrypted_msg.decode())

def decrypt_clicked_text():
    encoded_encrypted_msg = input_text1.get('1.0', END)
    privatekey_str = private_key_text2.get('1.0', END)
    privatekey = RSA.import_key(privatekey_str)
    decrypted_msg = decrypt_message_text(encoded_encrypted_msg.encode(), privatekey)
    output_text2.delete('1.0', END)
    output_text2.insert(END, decrypted_msg)

def generate_keys(modulus_length):
    privatekey = RSA.generate(modulus_length, e=65537)
    publickey = privatekey.publickey()
    return privatekey, publickey

from concurrent.futures import ThreadPoolExecutor
import os
def encrypt_file(input_file_path, publickey):
    try:
    
        with open(input_file_path, 'rb') as input_file:
            data = input_file.read()
            block_size = publickey.size_in_bytes() - 2 * SHA_DIGEST_SIZE - 2
            padded_data = pad(data, block_size)
            cipher = PKCS1_OAEP.new(publickey)
            encrypted_data = b''
            with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
                for i in range(0, len(padded_data), block_size):
                    chunk = padded_data[i:i+block_size]
                    encrypted_chunk = executor.submit(cipher.encrypt, chunk)
                    encrypted_data += encrypted_chunk.result()
                    # time.sleep(0.1)  
        with open(input_file_path, 'wb') as output_file:
            output_file.write(encrypted_data)
    except:
        output_text2.delete(1.0, END)
        output_text2.insert(END, "Encryption failed")


def pad(data, block_size):
    padding_size = block_size - len(data) % block_size
    padding = bytearray([padding_size % 256] * padding_size)
    padding[0] = 0x80
    return bytes(data + padding)


def decrypt_file(input_file_path, privatekey):
    try:
        with open(input_file_path, 'rb') as input_file:
            data = input_file.read()
            block_size = privatekey.size_in_bytes()
            cipher = PKCS1_OAEP.new(privatekey)
            decrypted_data = b''
            with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
                for i in range(0, len(data), block_size):
                    chunk = data[i:i+block_size]
                    decrypted_chunk = executor.submit(cipher.decrypt, chunk)
                    decrypted_data += decrypted_chunk.result()
                unpadded_data = unpad(block_size, decrypted_data)
        temp_file_path = input_file_path + '.temp'
        with open(temp_file_path, 'wb') as output_file:
            output_file.write(unpadded_data)
        try:
            os.replace(temp_file_path, input_file_path)
        except OSError:
            os.remove(input_file_path)
            os.rename(temp_file_path, input_file_path)
    except DecryptionError as e:
        output_text2.delete(1.0, END)
        output_text2.insert(END, f"Decryption failed: {e.message}")


def unpad(block_size,data):
    padding_size = data[-1]
    if padding_size > block_size:
        raise ValueError("Incorrect padding")
    unpadded_data = data[:-padding_size]

    return data[:-padding_size]


def generate_clicked(private_key_text, public_key_text, modulus_length):
    status.delete(1.0,END)
    status.insert(END, "Generating Keys...")
   
    privatekey, publickey = generate_keys(modulus_length)
    
    private_key_text.delete(1.0, END)
    private_key_text.insert(END, privatekey.export_key().decode())
    public_key_text.delete(1.0, END)
    public_key_text.insert(END, publickey.export_key().decode())
    status.delete(1.0,END)
    status.insert(END, "Ready")
    

def encrypt_clicked(public_key_text,input):
    if(input=="file"):
    
        if input_file_path:
            try:
                public_key = RSA.import_key(public_key_text.get(1.0, END))
            except:
                output_text2.delete(1.0, END)
                output_text2.insert(END, "Incorrect RSA Key...")
            else:
                try:
                    encrypt_file(input_file_path, public_key)
                    output_text.delete(1.0, END)
                    output_text.insert(END, f"Encryption successful and file saved on {input_file_path}")
                except:
                    output_text.delete(1.0, END)
                    output_text.insert(END, "Encryption Failed")
    else:
        encrypt_clicked_text()

def decrypt_clicked(private_key_text2,input):
    if(input=="file"):
        
        if input_file_path:
            try:
                private_key = RSA.import_key(private_key_text2.get(1.0, END))
            except:
                output_text2.delete(1.0, END)
                output_text2.insert(END, "Incorrect RSA Key...")
            else:
                try:
                    decrypt_file(input_file_path, private_key)
                    output_text2.delete(1.0, END)
                    output_text2.insert(END, f"Decryption successful and saved to path {input_file_path}")
                except DecryptionError as e:
                    output_text2.delete(1.0, END)
                    output_text2.insert(END, f"Decryption failed: {e.message}")
    else:
        decrypt_clicked_text()
def check(message):
    if(message=="Status: File save successfully"):
        status.delete('1.0',END)
        status.insert(END, "Status: File save successfully")
    else:
        status.delete('1.0',END)
        status.insert(END, "Status: Ready")

def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(output_text.get(1.0, END))
        status.delete('1.0',END)
        status.insert(END, "Status: File save successfully")
    else:
        status.delete('1.0',END)
        status.insert(END, "Status: File save cancelled")
def save_file2():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(output_text2.get(1.0, END))
        status.delete('1.0',END)
        status.insert(END, "Status: File save successfully")
    else:
        status.delete('1.0',END)
        status.insert(END, "Status: File save cancelled")
    

def save_key_public(public_key_text,output_text):
    if(public_key_text.get(1.0,END)==""):
        output_text.delete(1.0, END)
        output_text.insert(END, "Empty!")
        return
    public_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
    # private_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
    if public_key_path:
        with open(public_key_path, "wb") as f:
            public_key=RSA.import_key(public_key_text.get(1.0, END))
            f.write(public_key.export_key(format="PEM"))
    output_text.delete(1.0, END)
    output_text.insert(END, f"Public Key Successfully Saved on {public_key_path}")

def save_key_private(private_key_text,output_text):
    if(private_key_text.get(1.0,END)==""):
        output_text.delete(1.0, END)
        output_text.insert(END, "Empty!")
        return
    private_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
    # private_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
    if private_key_path:
        with open(private_key_path, "wb") as f:
            private_key=RSA.import_key(private_key_text.get(1.0, END))
            f.write(private_key.export_key(format="PEM"))
    output_text.delete(1.0, END)
    output_text.insert(END, f"Public Key Successfully Saved on {private_key_path}")
    


def browse_pem(private_key_text2,output_text2):
    file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if file_path:
        try:
            with open(file_path, 'r') as f:
                private_key_text2.delete(1.0, END)
                private_key_text2.insert(END, f.read())
            output_text2.delete(1.0, END)
            output_text2.insert(END, "PEM file loaded successfully!")
        except Exception as e:
            output_text.delete(1.0, END)
            output_text.insert(END, f"Error loading PEM file: {str(e)}")
      

# save_keys_button = Button(root, text="Save Keys", command=save_keys)
# save_keys_button.grid(row=4, column=0, pady=10)

input_file_path=""

    

root = Tk()
root.title("Encryption using Local/Private Key")
root.iconbitmap("icon.ico")
root.resizable(False, False)
status_update="Ready"
nb = ttk.Notebook(root)
nb.grid(row=0, column=0, padx=0, pady=0)
status = Text(root, bd=1, width=124, height=1, relief=SUNKEN)
status.insert('1.0', 'Status: Ready')
status.config(state='disabled')
status.grid(row=1, column=0, columnspan=3, padx=0, pady=0, sticky="nw")
rsa_length=1024

# status.delete('1.0',END)
# status.insert(END, status_update)
# create the encryption tab
encryption_tab = Frame(nb)
nb.add(encryption_tab, text="Encryption")
encryption_tab.grid_columnconfigure(1, weight=1)

encryption_frame1 = LabelFrame(encryption_tab,height=50, width=403,takefocus=0)
encryption_frame1.grid(row=0, column=0, padx=7, pady=7, sticky="nw")

input_type = StringVar()
input_type.set("file")
lf1 = LabelFrame(encryption_frame1, width=600, height=0)
lf1.grid(row=0,column=0,sticky="w",padx=7, pady=7)
file_radio = ttk.Radiobutton(lf1, text="File", variable=input_type, value="file", command=lambda: input_type_changed())
file_radio.grid(row=0, column=0, padx=7, pady=7,sticky="w")

output_text3 = Text(lf1, width=54, height=1)
output_text3.grid(row=1, column=0, padx=7, pady=7,sticky="e")
output_text3.config(state="disabled")
output_text3.delete('1.0', END)
output_text3.insert(END,"Select the file..")

Browse_button = ttk.Button(lf1, text="Browse...", command=lambda: hello(input_file_path))
Browse_button.grid(row=2, column=0, padx=7, pady=7, sticky="w")
# Browse_button.config(state="disabled")
# output_text3.config(state="disabled")


lf = LabelFrame(encryption_frame1, width=600, height=0)
lf.grid(row=1,column=0,sticky="w",padx=7, pady=7)


text_radio = ttk.Radiobutton(lf, text="Text", variable=input_type, value="text", command=lambda: input_type_changed())
text_radio.grid(row=0, column=0, padx=7, pady=7,sticky="w")

input_label = Label(lf, text="Input Text:")
input_label.grid(row=1, column=0, sticky="w",padx=7, pady=7)

input_text = Text(lf, width=54, height=5)
input_text.grid(row=2, column=0, columnspan=2,padx=7, pady=7)

clear_button = ttk.Button(lf, text="Clear", command=lambda: input_text.delete(1.0, END))
clear_button.grid(row=3, column=0, padx=7, pady=7,sticky="w")

# text_frame=LabelFrame(encryption_frame1,height=502,width=80,takefocus=0).grid(row=0,column=0,padx=7, pady=7,sticky="w")
# text_encrypt=Label(encryption_frame1, text="Text Input:")
# text_encrypt.grid(row=1, column=0, padx=7, pady=7, sticky="w")



length_frame = LabelFrame(encryption_frame1, text="RSA Length", padx=7, pady=7)
length_frame.grid(row=3, column=0, sticky=W+E+N+S, padx=7, pady=7)

rsa_1024 = ttk.Radiobutton(length_frame, text="1024 bits", variable=rsa_length, value=1024)
rsa_1024.pack(anchor=W)

rsa_2048 = ttk.Radiobutton(length_frame, text="2048 bits", variable=rsa_length, value=2048)
rsa_2048.pack(anchor=W)

rsa_3072 = ttk.Radiobutton(length_frame, text="3072 bits", variable=rsa_length, value=3072)
rsa_3072.pack(anchor=W)

rsa_4096 = ttk.Radiobutton(length_frame, text="4096 bits", variable=rsa_length, value=4096)
rsa_4096.pack(anchor=W)

ttk.Button(encryption_frame1, text="Encrypt File", command=lambda: encrypt_clicked(public_key_text,input_type.get())).grid(row=4, column=0, padx=7, pady=7,sticky="e")
ttk.Button(encryption_frame1, text="Generate Keys", command=lambda: generate_clicked(private_key_text, public_key_text, rsa_length)).grid(row=4, column=0, padx=7, pady=7,sticky="w")

encryption_frame2 = LabelFrame(encryption_tab,height=502, width=403,takefocus=0)
encryption_frame2.grid(row=0, column=1, padx=7, pady=7, sticky="ne")

private_key_label = ttk.Label(encryption_frame2, text="Private Key:")
private_key_label.grid(row=1, column=0, padx=7, pady=0, sticky="w")

private_key_text = Text(encryption_frame2, width=60, height=10)
private_key_text.grid(row=2, column=0, columnspan=3, padx=7, pady=7)

private_key_clear_button = ttk.Button(encryption_frame2, text="Clear",style="Custom.TButton",command=lambda: private_key_text.delete(1.0, END))
private_key_clear_button.grid(row=3, column=0, padx=7, pady=7,sticky="w")

private_key_copy_button = ttk.Button(encryption_frame2, text="Copy", command=lambda: root.clipboard_append(private_key_text.get(1.0, END)))
private_key_copy_button.grid(row=3, column=1, padx=7, pady=7)

save_private_button = ttk.Button(encryption_frame2, text="Save Private Key", command=lambda: save_key_private(private_key_text,output_text))
save_private_button.grid(row=3, column=2)

public_key_label = Label(encryption_frame2, text="Public Key:")
public_key_label.grid(row=4, column=0, padx=7, pady=0, sticky="w")

public_key_text = Text(encryption_frame2, width=60, height=10)
public_key_text.grid(row=5, column=0, columnspan=3, padx=7, pady=7)

public_key_clear_button = ttk.Button(encryption_frame2, text="Clear", command=lambda: public_key_text.delete(1.0, END))
public_key_clear_button.grid(row=6, column=0, padx=7, pady=7,sticky="w")

public_key_copy_button = ttk.Button(encryption_frame2, text="Copy", command=lambda: root.clipboard_append(public_key_text.get(1.0, END)))
public_key_copy_button.grid(row=6, column=1, padx=7, pady=7)

save_public_button = ttk.Button(encryption_frame2, text="Save Public Key", command=lambda: save_key_public(public_key_text,output_text))
save_public_button.grid(row=6, column=2)


# Button(encryption_tab, text="Decrypt File", command=lambda: decrypt_clicked(private_key_text)).grid(row=5, column=1, padx=7, pady=7)
outpit_label = Label(encryption_frame2, text="Output")
outpit_label.grid(row=7, column=0, padx=7, pady=0, sticky="w")

output_text = Text(encryption_frame2, width=60, height=5)
output_text.grid(row=8, column=0, columnspan=3, padx=7, pady=7)
save_button = ttk.Button(encryption_frame2, text="Save As...", command=save_file)
save_button.grid(row=9, column=1, padx=7, pady=5)
clear_button_2=ttk.Button(encryption_frame2, text="Clear",style="Custom.TButton",command=lambda: output_text.delete(1.0, END))
clear_button_2.grid(row=9,column=0,padx=7,pady=5,sticky="w")



# create the decryption tab
decryption_tab = Frame(nb)
nb.add(decryption_tab, text="Decryption")
decryption_tab.grid_columnconfigure(1, weight=1)
decryption_frame1 = LabelFrame(decryption_tab,height=50, width=403,takefocus=0)
decryption_frame1.grid(row=0, column=0, padx=7, pady=7, sticky="nw")

input_type2 = StringVar()
input_type2.set("file")
lf2 = LabelFrame(decryption_frame1, width=600, height=0)
lf2.grid(row=0,column=0,sticky="w",padx=7, pady=7)
file_radio1 = ttk.Radiobutton(lf2, text="File", variable=input_type2, value="file", command=lambda: input_type_changed2())
file_radio1.grid(row=0, column=0, padx=7, pady=7,sticky="w")

output_text4 = Text(lf2, width=54, height=1)
output_text4.grid(row=1, column=0, padx=7, pady=7,sticky="e")
output_text4.config(state="disabled")
output_text4.delete('1.0', END)
output_text4.insert(END,"Select the file..")

Browse_button1 = ttk.Button(lf2, text="Browse...", command=lambda: hello2(input_file_path))
Browse_button1.grid(row=2, column=0, padx=7, pady=7, sticky="w")
# Browse_button.config(state="disabled")
# output_text3.config(state="disabled")


lf3 = LabelFrame(decryption_frame1, width=600, height=0)
lf3.grid(row=1,column=0,sticky="w",padx=7, pady=7)


text_radio1 = ttk.Radiobutton(lf3, text="Text", variable=input_type2, value="text", command=lambda: input_type_changed2())
text_radio1.grid(row=0, column=0, padx=7, pady=7,sticky="w")

input_label1 = Label(lf3, text="Input Text For Decryption:")
input_label1.grid(row=1, column=0, sticky="w",padx=7, pady=7)

input_text1 = Text(lf3, width=54, height=5)
input_text1.grid(row=2, column=0, columnspan=2,padx=7, pady=7)

clear_button1 = ttk.Button(lf3, text="Clear", command=lambda: input_text1.delete(1.0, END))
clear_button1.grid(row=3, column=0, padx=7, pady=7,sticky="w")










private_key_label2 = Label(decryption_frame1, text="Private Key:")
private_key_label2.grid(row=2, column=0, padx=7, pady=7, sticky="w")

private_key_text2 = Text(decryption_frame1, width=60, height=10)
private_key_text2.grid(row=3, column=0, columnspan=3, padx=7, pady=7,sticky="w")

private_key_clear_button2 = ttk.Button(decryption_frame1, text="Clear",style="Custom.TButton",command=lambda: private_key_text2.delete(1.0, END))
private_key_clear_button2.grid(row=4, column=0, padx=7, pady=7,sticky="w")

# paste_button = ttk.Button(decryption_frame1, text="Paste", command=lambda: root.clipboard_append(private_key_text2.get(1.0, END)))
# paste_button.grid(row=2, column=1, padx=5, pady=5, sticky="w")

# private_key_copy_button2 = ttk.Button(decryption_frame1, text="Copy", command=lambda: root.clipboard_append(private_key_text.get(1.0, END)))
# private_key_copy_button2.grid(row=4, column=1, padx=7, pady=7)



# ttk.Button(encryption_frame1, text="Encrypt File", command=lambda: encrypt_clicked(public_key_text,input_type.get())).grid(row=4, column=0, padx=7, pady=7,sticky="e")


decryption_frame2 = LabelFrame(decryption_tab,height=502, width=403,takefocus=0)
decryption_frame2.grid(row=0, column=1, padx=7, pady=7, sticky="nw")

outpit_label1 = Label(decryption_frame2, text="Output")
outpit_label1.grid(row=0, column=0, padx=7, pady=0, sticky="w")
output_text2= Text(decryption_frame2, width=60, height=5)
output_text2.grid(row=1, column=0, columnspan=3, padx=7, pady=7)

browse_button_private = ttk.Button(decryption_frame1, text="Browse PEM file", command=lambda: browse_pem(private_key_text2,output_text2))
browse_button_private.grid(row=4, column=0, padx=0, pady=5, sticky="e")
ttk.Button(decryption_frame1, text="Decrypt File", command=lambda: decrypt_clicked(private_key_text2,input_type2.get())).grid(row=53, column=0, padx=7, pady=7,sticky="w")
save_button_private = ttk.Button(decryption_frame2, text="Save As...", command=save_file)
save_button_private.grid(row=2, column=1, padx=7, pady=5)
clear_button_21=ttk.Button(decryption_frame2, text="Clear",style="Custom.TButton",command=lambda: output_text2.delete(1.0, END))
clear_button_21.grid(row=2,column=0,padx=7,pady=5,sticky="w")
def hello(input):
    global input_file_path
    input = filedialog.askopenfilename()
    input_file_path=input
    output_text3.delete('1.0', END)
    output_text3.insert(END,f"{input_file_path}")
def hello2(input):
    global input_file_path
    input = filedialog.askopenfilename()
    input_file_path=input
    output_text4.delete('1.0', END)
    output_text4.insert(END,f"{input_file_path}")
def input_type_changed():
    if input_type.get() == "file":
        # global input_type
        # input_type="file"
        input_text.delete('1.0',END)
        Browse_button.config(state="normal")
        output_text3.config(state="normal")
        input_text.config(state="disabled")
        clear_button.config(state="disabled")
        output_text3.delete('1.0', END)
        output_text3.insert(END,"Select File...")
    else:
        # global input_type
        # input_type="text"
        output_text3.delete('1.0', END)
        Browse_button.config(state="disabled")
        output_text3.config(state="disabled")
        input_text.config(state="normal")
        clear_button.config(state="normal")

def input_type_changed2():
    if input_type2.get() == "file":
        
        input_text1.delete('1.0',END)
        Browse_button1.config(state="normal")
        output_text4.config(state="normal")
        input_text1.config(state="disabled")
        clear_button1.config(state="disabled")
        output_text4.delete('1.0', END)
        output_text4.insert(END,"Select File...")
    else:
        output_text4.delete('1.0', END)
        Browse_button1.config(state="disabled")
        output_text4.config(state="disabled")
        input_text1.config(state="normal")
        clear_button1.config(state="normal")

input_type.trace("w", lambda *args: input_type_changed())
input_type2.trace("w", lambda *args: input_type_changed2())

root.mainloop()
