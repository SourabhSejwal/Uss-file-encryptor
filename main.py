__title__ = "Encryption using Local Key"

__version__ = "1.0.0"


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os


from tkinter import (
    NORMAL, DISABLED, WORD, FLAT, END, LEFT,
    X, Y, RIGHT, LEFT, BOTH,
    TOP, SUNKEN,  BOTTOM, W,YES, W,
    Text, Toplevel, Pack, Grid, Tk,
    Place, IntVar, StringVar, Label, Frame,
    filedialog, messagebox, TclError
)

TkLabel = Label
from tkinter.ttk import (
    Entry, Button, Label, LabelFrame, Frame,
    Widget, Notebook, Radiobutton, Checkbutton,
    Scrollbar
    
)

try:
    
    from re import findall
    from threading import Thread
    from typing import Optional, Callable, final
    from urllib.request import urlopen
    from hurry.filesize import size, alternative
    from markdown import markdown
    # from tkinterweb import HtmlFrame
    from requests import get
    from webbrowser import open as openweb
    from string import ascii_letters, digits
    from datetime import datetime
    from random import randint, choice
    from ttkthemes import ThemedStyle
     
    
    
    
    from Crypto.Cipher import AES, PKCS1_OAEP, DES3
    from Crypto.PublicKey import RSA
    
    from Crypto.Protocol.KDF import scrypt
    from Crypto.Random import get_random_bytes

    import base64, os,  pyperclip, binascii
    import functools, multipledispatch,  inspect

except (ModuleNotFoundError, ImportError) as exc:
    # If an error occurs while importing a module, show an error message explaining how to install the module, and exit the program
    lib: str = exc.msg.replace("No module named '", "").replace("'", "")
    match lib:
        case "Crypto.Cipher" | "Crypto.PublicKey" | "Crypto.Signature" | "Crypto.Hash" | "Crypto.Protocol.KDF" | "Crypto.Random":
            lib_name = "pycryptodome"
        case _:
            lib_name = lib
    messagebox.showerror("Missing library", "A required library named \"{name}\" is missing! You should be able to install that library with the following command:\n\npython -m pip install {name}\n\nIf that doesn't work, try googling.".format(name=lib_name))
    __import__("sys").exit()

def threaded(function: Callable):
    """
    Function decorator to run the function in a separate thread, using "threading" module
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return Thread(target=function, args=args, kwargs=kwargs).start()
        except Exception:
            pass
    return wrapper




def traffic_controlled(function: Callable):
    """
    Function decorator for the 'encrypt' and 'decrypt' methods of this class
    in order to prevent stack overflow by waiting for the previous encryption
    process to finish if it's still in progress before starting a new thread
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        # args[0] is always 'self' in methods of a class
        self: Cryptography = args[0]
        root: Interface = self.master
        if function.__name__ == "encrypt":
            root.mainNotebook.encryptionFrame.encryptButton.configure(state=DISABLED if bool(root.dataSourceVar.get()) else NORMAL if not bool(root.mainNotebook.encryptionFrame.algorithmSelect.index(root.mainNotebook.encryptionFrame.algorithmSelect.select())) else DISABLED)
            if self.encryption_busy and self.encryption_busy is not None:
                # If an encryption is in progress, don't create a new thread and return instead
                return
            # If no encryptions are in progress, set the attribute representing whether an encryption is in progress or not to True
            self.encryption_busy = True
            try:
                # And start the encryption
                return function(*args, **kwargs)
            except Exception: ...
            finally:
                # Even if the encryption fails, set the attribute back to False to allow new requests
                self.encryption_busy = False
                root.mainNotebook.encryptionFrame.encryptButton.configure(state=NORMAL)
        else:
            root.mainNotebook.decryptionFrame.decryptButton.configure(state=DISABLED) if bool(root.decryptSourceVar.get()) else None
            if self.decryption_busy and self.decryption_busy is not None:
                # Likewise, if a decryption is in progress, don't create a new thread and return instead
                return
            self.decryption_busy = True
            try:
                return function(*args, **kwargs)
            except Exception: ...
            finally:
                self.decryption_busy = False
                root.mainNotebook.decryptionFrame.decryptButton.configure(state=NORMAL)
    return wrapper

class state_control_function(object):
    def __init__(self, cls: type):
        self.cls = cls

    def __call__(self, function: Callable):
        self.cls.root.scfs.append({'method': function, 'class': lambda: self._find_class(self.cls, function)})
        return function

    @staticmethod
    def _find_class(cls: type, function: Callable) -> type:
        return [subcls for subcls in [getattr(cls, subcls) for subcls in cls.__dict__ if not isinstance(getattr(cls, subcls), str)] if hasattr(subcls, function.__name__)][0]

class selfinjected(object):
    def __init__(self, name: str):
        self.name = name
    def __call__(self, function: Callable):
        function.__globals__[self.name] = function
        return function

@final
class Utilities(object):
    """
    Utilities class for some useful methods that may help me in the future
    """
    def __init__(self, root: Tk):
        self.root = root
        
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @classmethod
    def get_master_class(utils, meth: Callable) -> type:
        """
        Returns the class of the given method
        """
        if isinstance(meth, functools.partial):
            return utils.get_master_class(meth.func)
        if inspect.ismethod(meth) or (inspect.isbuiltin(meth) and getattr(meth, '__self__', None) is not None and getattr(meth.__self__, '__class__', None)):
            for cls in inspect.getmro(meth.__self__.__class__):
                if meth.__name__ in cls.__dict__:
                    return cls
            meth: Callable = getattr(meth, '__func__', meth)
        if inspect.isfunction(meth):
            cls: type = getattr(inspect.getmodule(meth),
                        meth.__qualname__.split('.<locals>', 1)[0].rsplit('.', 1)[0],
                        None)
            if isinstance(cls, type):
                return cls
        return getattr(meth, '__objclass__', None)
    
    @classmethod
    def get_inner_classes(utils, cls: type) -> list[type]:
        """
        Returns a list of all inner classes of the given class
        """
        return [cls_attr for cls_attr in cls.__dict__.values() if inspect.isclass(cls_attr)]

@final
class Cryptography(object):
    def __init__(self, master: Tk):
        self.master = self.root = master
        self.__encryption_busy = False
        self.__decryption_busy = False
    
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @staticmethod
    def generate_key(length: int = 32) -> str:
        """
        Static method to generate and return a random encryption key in the given length (defaults to 32)
        """
        if not isinstance(length, int):
            length = int(length)
        key = str()
        for _ in range(length):
            random = randint(1, 32)
            if random in range(0, 25):
                key += choice(ascii_letters)
            elif random in range(0, 30):
                key += choice(digits)
            elif random >= 30:
                key += choice("!'^+%&/()=?_<>#${[]}\|__--$__--")
        return key

    @staticmethod
    def derivate_key(password: str | bytes) -> Optional[bytes]:
        """
        Static method to derivate an encryption key from a password (using KDF protocol)
        """
        try:
            return base64.urlsafe_b64encode(scrypt(password.decode("utf-8") if isinstance(password, bytes) else password, get_random_bytes(16), 24, N=2**14, r=8, p=1))
        except Exception:
            return None

    @staticmethod
    def get_key(root: Tk, entry: Optional[Entry] = None) -> Optional[str]:
        """
        Multiply dispatched static method to get the encryption key from the given file and insert it into the optionally given entry
        """
        path = filedialog.askopenfilename(title="Open a key file", filetypes=[("Encrypt'n'Decrypt key file", "*.key"), ("Text document", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        match os.path.getsize(path):
            case 16 | 24 | 32:
                with open(path, mode="rb") as file:
                    index = file.read()
                try:
                    AES.new(index, AES.MODE_CFB, iv=get_random_bytes(AES.block_size))
                except Exception:
                    messagebox.showwarning("Invalid key file", "The specified file does not contain any valid key for encryption.")
                    # root.logger.error("Key file with no valid key inside was specified.")
                    return
                else:
                    if entry:
                        entry.replace(index.decode("utf-8"))
                    return index.decode("utf-8")
            case 76 | 88 | 96:
                with open(path, mode="rb") as file:
                    index = file.read()
                for s, e in zip(range(0, len(index)), range(int(len(index) / 3), len(index))):
                    try:
                        result = AES.new(index[s:e], AES.MODE_CFB, iv=base64.urlsafe_b64decode(index.replace(index[s:e], b""))[:16]).decrypt(base64.urlsafe_b64decode(index.replace(index[s:e], b""))[16:]).decode("utf-8")
                        if entry:
                            entry.replace(result)
                        return result
                    except Exception:
                        continue
            case _:
                messagebox.showwarning("Invalid key file", "The specified file does not contain any valid key for encryption.")
                # root.logger.error("Key file with no valid key inside was specified.")
                return

    @classmethod
    def save_key(cls, key: str | bytes, root: Tk) -> None:
        """
        Static method to save the encryption key to a file
        """
        if isinstance(key, str):
            key = bytes(key, "utf-8")
        path = filedialog.asksaveasfilename(title="Save encryption key", initialfile="Encryption Key.key", filetypes=[("Encrypt'n'Decrypt key file", "*.key"), ("Text document", "*.txt"), ("All files", "*.*")], defaultextension="*.key")
        if ''.join(path.split()) == '':
            # If save dialog was closed without choosing a file, simply return
            return
        if os.path.splitext(path)[1].lower() == ".key":
            # If the file extension is .key, save the key using the special algorithm
            _key = cls.generate_key(32)

            iv = get_random_bytes(AES.block_size)
            aes = AES.new(bytes(_key, "utf-8"), AES.MODE_CFB, iv=iv)
            raw = iv + aes.encrypt(key)
            res = base64.urlsafe_b64encode(raw).decode()

            index = randint(0, len(res))
            final = res[:index] + _key + res[index:]
            try:
                os.remove(path)
            except:
                pass
            finally:
                with open(path, encoding = 'utf-8', mode="w") as file:
                    file.write(str(final))
                # root.logger.debug("Encryption key has been saved to \"{}\"".format(path))
        else:
            # Otherwise, simply save the key onto the file
            with open(path, encoding="utf-8", mode="wb") as file:
                file.write(key)

    
    def update_status(self, status: str = "Ready") -> None:
        """
        A simple method to simplify updating the status bar of the program
        """
        root: Interface = self.root
        root.statusBar.configure(text=f"Status: {status}")
        # Call the 'update()' method manually in case the interface is not responding at the moment
        root.update()

    @property
    def encryption_busy(self) -> bool:
        """
        Property to check if an encryption process is currently in progress
        """
        return self.__encryption_busy
    @encryption_busy.setter
    def encryption_busy(self, value: bool) -> None:
        if self.__encryption_busy == value and value:
            raise Exception
        self.__encryption_busy = value

    @property
    def decryption_busy(self) -> bool:
        """
        Property to check if a decryption process is currently in progress
        """
        return self.__decryption_busy
    @decryption_busy.setter
    def decryption_busy(self, value: bool) -> None:
        if self.__decryption_busy == value and value:
            raise Exception
        self.__decryption_busy = value

    @threaded
    @traffic_controlled
    
    def encrypt(self) -> None:
        root: Interface = self.master

        if not bool(root.mainNotebook.encryptionFrame.algorithmSelect.index(root.mainNotebook.encryptionFrame.algorithmSelect.select())):
            # If the "Symmetric Key Encryption" tab is selected...
            if not bool(root.keySourceSelection.get()):
                # If the user has chosen to generate a new key, generate one
                self.update_status("Generating the key...")
                key: bytes = self.generate_key(int(root.generateRandomAESVar.get() if not bool(root.generateAlgorithmSelection.get()) else root.generateRandomDESVar.get()) / 8).encode("utf-8")
            else:
                # Otherwise, use the key the user has provided
                key: bytes = root.keyEntryVar.get().encode("utf-8")

            self.update_status("Creating the cipher...")
            try:
                # Try to create the cipher (either AES or DES3 object according to the user's choice) with the given/generated key
                if (not bool(root.generateAlgorithmSelection.get()) and not bool(root.keySourceSelection.get())) or (not bool(root.entryAlgorithmSelection.get()) and bool(root.keySourceSelection.get())):
                    iv = get_random_bytes(AES.block_size)
                    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                else:
                    iv = get_random_bytes(DES3.block_size)
                    cipher = DES3.new(key, mode=DES3.MODE_OFB, iv=iv)
            except ValueError as details:
                if not len(key) in [16, 24, 32 if "AES" in str(details) else False]:
                    # If the key length is not valid, show an error message
                    messagebox.showerror("Invalid key length", "The length of the encryption key you've entered is invalid! It can be either 16, 24 or 32 characters long.")
                    # root.logger.error("Key with invalid length was specified")
                    self.update_status("Ready")
                    return
                else:
                    # If the key length is valid, but the key contains invalid characters, show an error message
                    messagebox.showerror("Invalid key", "The key you've entered is invalid for encryption. Please enter another key or consider generating one instead.")
                    # root.logger.error("Invalid key was specified")
                    self.update_status("Ready")
                    return

            datas: list[str | bytes] = []
            if not bool(root.dataSourceVar.get()):
                # If the user has chosen to encrypt a plain text, simply put the text from the entry to the datas list
                datas.append(bytes(root.textEntryVar.get(), "utf-8"))
            else:
                # Otherwise, split the file paths from the entry using '|' character and put in the datas list
                path: str = root.mainNotebook.encryptionFrame.fileEntry.get()
                for filename in path.split('|'):
                    datas.append(filename)
            
            # Iterate over the data(s) to be encrypted
            for raw, index in [(raw.lstrip(), datas.index(raw)) for raw in datas]:
                if isinstance(raw, str):
                    # If the data is an instance of str, by other means, a file path, open the file and convert to bytes
                    try:
                        self.update_status(f"Reading the file (file {index + 1}/{len(datas)})...")
                        with open(raw, mode="rb") as file:
                            data: bytes = file.read()
                    except PermissionError:
                        messagebox.showerror("Access denied", f"Access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                        # root.logger.error(f"Read permission for the file named \"{os.path.basename(raw)}\" that was specified has been denied, skipping")
                        continue
                else:
                    # Otherwise, just use the current data as is
                    data: bytes = raw
                try:
                    self.update_status(f"Encrypting (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Encrypting...")
                    # Encrypt the data and combine it with the IV used
                    root.lastEncryptionResult = iv + cipher.encrypt(data)
                except MemoryError:
                    # If the computer runs out of memory while encrypting (happens when encrypting big files), show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while encrypting the file. Try closing other applications or restart your computer.")
                    # root.logger.error("Device has run out of memory while encrypting, encryption was interrupted")
                    self.update_status("Ready")
                    return
                # Delete the data variable since we have the encrypted data held on another variable, in order to free up some memory
                del data
                self.update_status(f"Encoding (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Encoding the result...")
                try:
                    try:
                        # Encode the result using base64
                        root.lastEncryptionResult = base64.urlsafe_b64encode(root.lastEncryptionResult).decode("utf-8")
                    except TypeError:
                        self.update_status("Ready")
                        return
                    if bool(root.encryptWriteFileContentVar.get()) and bool(root.dataSourceVar.get()):
                        self.update_status(f"Writing to the file (file {index + 1}/{len(datas)})...")
                        try:
                            with open(raw, mode="wb") as file:
                                file.write(root.lastEncryptionResult.encode("utf-8"))
                            if len(datas) != 1:
                                del root.lastEncryptionResult
                        except PermissionError:
                            # If the program doesn't have write access to the file, show an error message
                            if messagebox.askyesnocancel("Access denied", f"Write access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied, therefore the result could not have been overwritten to the file. Do you want to save the encrypted data as another file?"):
                                newpath = filedialog.asksaveasfilename(title="Save encrypted data", initialfile=os.path.basename(path[:-1] if path[-1:] == "\\" else path), initialdir=os.path.dirname(path), filetypes=[("All files","*.*")], defaultextension="*.key")
                                if newpath == "":
                                    failure = True
                                    # root.logger.error("Write permission for the file specified has been denied, encryped data could not be saved to the destination")
                                    break
                                else:
                                    with open(newpath, mode="wb") as file:
                                        file.write(bytes(root.lastEncryptionResult, "utf-8"))
                            # root.logger.error("Write permission for the file specified has been denied, encrypted data could not be saved to the destination")
                            self.update_status("Ready")
                            failure = True
                            return
                        except OSError as details:
                            if "No space" in str(details):
                                # If no space left on device to save the result, show an error message
                                messagebox.showerror("No space left", "There is no space left on your device. Free up some space and try again.")
                                # root.logger.error("No space left on device, encrypted data could not be saved to the destination")
                                self.update_status("Ready")
                                failure = True
                                pass

                except MemoryError:
                    # Again, if the computer runs out of memory while encoding, show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while encoding the result. Try closing other applications or restart your computer.")
                    # root.logger.error("Device has run out of memory while encoding, encryption was interrupted")
                    self.update_status("Ready")
                    return
                # Set the variables holding the key used and the file encrypted (if applicable) in order to be able to copy later
                root.lastEncryptionKey = key
                root.lastEncryptedFile = root.fileEntryVar.get() if bool(root.dataSourceVar.get()) else None

            failure = False
                            
            if len(datas) != 1 and bool(root.dataSourceVar.get()):
                # If multiple files were encrypted, don't show the result (because how are we supposed to show anyway)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="gray", wrap=WORD)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.replace("Encrypted data is not being displayed because multiple files were selected to be encrypted.")
                if hasattr(root, 'lastEncryptionResult'):
                    del root.lastEncryptionResult
            elif hasattr(root, "lastEncryptionResult") and len(root.lastEncryptionResult) > 15000:
                # If one file was chosen or a plain text was entered to be encrypted, but the result is over 15.000 characters, don't show the result
                root.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="gray", wrap=WORD)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.replace("Encrypted data is not being displayed because it is longer than 15.000 characters.")
                if hasattr(root, 'lastEncryptionResult'):
                    del root.lastEncryptionResult
            else:
                # Otherwise, just show it
                root.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="black", wrap=None)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.replace(root.lastEncryptionResult)

            root.mainNotebook.encryptionFrame.outputFrame.AESKeyText.replace(key.decode("utf-8"))
            

            self.update_status("Ready")
            # if not failure:
            #     # If there was no error while writing the result to the file, log the success
            #     if not bool(root.keySourceSelection.get()):
            #         # root.logger.info(f"{'Entered text' if not bool(root.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(root.generateAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm")
            #     else:
            #         # root.logger.info(f"{'Entered text' if not bool(root.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(root.entryAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm")

        else:
            data = root.mainNotebook.encryptionFrame.textEntry.get()
            self.update_status("Generating the key...")
            key = RSA.generate(root.generateRandomRSAVar.get() if root.generateRandomRSAVar.get() >= 1024 else root.customRSALengthVar.get())
            publicKey = key.publickey()
            privateKey = key.exportKey()

            self.update_status("Defining the cipher...")
            cipher = PKCS1_OAEP.new(publicKey)

            self.update_status("Encrypting...")
            try:
                encrypted = cipher.encrypt(data.encode("utf-8") if isinstance(data, str) else data)
            except ValueError:
                messagebox.showerror(f"{'Text is too long' if not bool(root.dataSourceVar) else 'File is too big'}", "The {} is too {} for RSA-{} encryption. Select a longer RSA key and try again.".format('text you\'ve entered' if not bool(root.dataSourceVar.get()) else 'file you\'ve specified', 'long' if not bool(root.dataSourceVar.get()) else 'big', root.generateRandomRSAVar.get()))
                # root.logger.error(f"Too {'long text' if not bool(root.dataSourceVar) else 'big file'} was specified, encryption was interrupted")
                self.update_status("Ready")
                return

            root.mainNotebook.encryptionFrame.outputFrame.outputText.replace(base64.urlsafe_b64encode(encrypted).decode("utf-8"))
            root.mainNotebook.encryptionFrame.outputFrame.AESKeyText.clear()
            

            """
            decryptor = PKCS1_OAEP.new(RSA.import_key(privateKey))
            decrypted = decryptor.decrypt(encrypted)
            print('Decrypted:', decrypted.decode())
            """

            self.update_status("Ready")

    @threaded
    @traffic_controlled
   
    def decrypt(self) -> None:
        root: Interface = self.master

        if not bool(root.mainNotebook.decryptionFrame.algorithmSelect.index(root.mainNotebook.decryptionFrame.algorithmSelect.select())):
            self.update_status("Defining cipher...")

            datas: list[str | bytes] = []
            if not bool(root.decryptSourceVar.get()):
                # If the user has chosen to decrypt a plain text, simply put the text from the entry to the datas list
                datas.append(bytes(root.textDecryptVar.get(), "utf-8"))
            else:
                # Otherwise, split the file paths from the entry using '|' character and put in the datas list
                path: str = root.mainNotebook.decryptionFrame.fileDecryptEntry.get()
                for filename in path.split('|'):
                    datas.append(filename)
            
            # Iterate over the data(s) to be decrypted
            for raw, index in [(raw.lstrip(), datas.index(raw)) for raw in datas]:
                if isinstance(raw, str):
                    # If the data is an instance of str, by other means, a file path, open the file and convert to bytes
                    try:
                        self.update_status(f"Reading the file (file {index + 1}/{len(datas)})...")
                        with open(raw, mode="rb") as file:
                            data: bytes = file.read()
                    except PermissionError:
                        messagebox.showerror("Access denied", f"Access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                        # root.logger.error(f"Read permission for the file named \"{os.path.basename(raw)}\" that was specified has been denied, skipping")
                        continue
                else:
                    # Otherwise, just use the current data as is
                    data: bytes = raw
                self.update_status(f"Decoding (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Decoding...")
                try:
                    new_data: bytes = base64.urlsafe_b64decode(data)
                except Exception as exc:
                    messagebox.showerror("Unencrypted file", f"This file doesn't seem to be encrypted using {'AES' if not bool(root.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                    # root.logger.error("Unencrypted file was specified for decryption")
                    self.update_status("Ready")
                    return
                else:
                    if data == base64.urlsafe_b64encode(new_data):
                        data: bytes = new_data
                        del new_data
                    else:
                        messagebox.showerror("Unencrypted file", f"This file doesn't seem to be encrypted using {'AES' if not bool(root.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                        # root.logger.error("Unencrypted file was specified")
                        self.update_status("Ready")
                        return
                if 'cipher' not in locals():
                    iv = data[:16 if not bool(root.decryptAlgorithmVar.get()) else 8]
                    key = root.decryptKeyVar.get()[:-1 if root.decryptKeyVar.get().endswith("\n") else None].encode("utf-8")

                    try:
                        if not bool(root.decryptAlgorithmVar.get()):
                            cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                        else:
                            cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
                    except ValueError as details:
                        if len(iv) != 16 if not bool(root.decryptAlgorithmVar.get()) else 8:
                            messagebox.showerror("Unencrypted data", f"The text you've entered doesn't seem to be encrypted using {'AES' if not bool(root.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                            # root.logger.error("Unencrypted text was entered")
                            self.update_status("Ready")
                            return
                        elif not len(key) in [16, 24, 32 if "AES" in str(details) else False]:
                            messagebox.showerror("Invalid key length", "The length of the encryption key you've entered is invalid! It can be either 16, 24 or 32 characters long.")
                            # root.logger.error("Key with invalid length was entered for decryption")
                            self.update_status("Ready")
                            return
                        else:
                            messagebox.showerror("Invalid key", "The encryption key you've entered is invalid.")
                            # root.logger.error("Invalid key was entered for decryption")
                            self.update_status("Ready")
                            return
                try:
                    self.update_status(f"Decrypting (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Decrypting...")
                    # Decrypt the data
                    root.lastDecryptionResult = cipher.decrypt(data.replace(iv, b""))
                    
                except MemoryError:
                    # If the computer runs out of memory while decrypting (happens when encrypting big files), show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while decrypting the file. Try closing other applications or restart your computer.")
                    # root.logger.error("Device has run out of memory while decrypting, decryption was interrupted")
                    self.update_status("Ready")
                    return
                # Delete the data variable since we have the decrypted data held on another variable, in order to free up some memory
                del data
                try:
                    if bool(root.decryptWriteFileContentVar.get()) and bool(root.decryptSourceVar.get()):
                        self.update_status(f"Writing to the file (file {index + 1}/{len(datas)})...")
                        try:
                            with open(raw, mode="wb") as file:
                                file.write(root.lastDecryptionResult)
                            if len(datas) != 1:
                                del root.lastDecryptionResult
                        except PermissionError:
                            # If the program doesn't have write access to the file, show an error message
                            if messagebox.askyesnocancel("Access denied", f"Write access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied, therefore the result could not have been overwritten to the file. Do you want to save the encrypted data as another file?"):
                                newpath = filedialog.asksaveasfilename(title="Save encrypted data", initialfile=os.path.basename(path[:-1] if path[-1:] == "\\" else path), initialdir=os.path.dirname(path), filetypes=[("All files","*.*")], defaultextension="*.key")
                                if newpath == "":
                                    failure = True
                                    # root.logger.error("Write permission for the file specified has been denied, encryped data could not be saved to the destination")
                                    break
                                else:
                                    with open(newpath, mode="wb") as file:
                                        file.write(bytes(root.lastEncryptionResult, "utf-8"))
                            # root.logger.error("Write permission for the file specified has been denied, encrypted data could not be saved to the destination")
                            self.update_status("Ready")
                            failure = True
                            return
                        except OSError:
                            if "No space" in str(details):
                                # If no space is left on device to save the result, show an error message
                                messagebox.showerror("No space left", "There is no space left on your device. Free up some space and try again.")
                                # root.logger.error("No space left on device, encrypted data could not be saved to the destination")
                                self.update_status("Ready")
                                failure = True
                                pass

                except MemoryError:
                    # Again, if the computer runs out of memory while encoding, show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while encoding the result. Try closing other applications or restart your computer.")
                    # root.logger.error("Device has run out of memory while encoding, encryption was interrupted")
                    self.update_status("Ready")
                    return

            self.update_status("Displaying the result...")
            try:
                root.lastDecryptionResult = root.lastDecryptionResult.decode("utf-8")
            except UnicodeDecodeError as exc:
                if bool(root.decryptSourceVar.get()):
                    root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                    root.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because it's in an unknown encoding.")
                else:
                    messagebox.showerror("Invalid key", "The encryption key you've entered doesn't seem to be the right key. Make sure you've entered the correct key.")
                    # root.logger.error("Wrong key was entered for decryption")
                    self.update_status("Ready")
                    return
            except AttributeError:
                root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                root.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because multiple files were selected to be decrypted.")
            else:
                if not len(root.lastDecryptionResult) > 15000:
                    root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="black")
                    root.mainNotebook.decryptionFrame.decryptOutputText.replace(root.lastDecryptionResult)
                else:
                    root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                    root.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because it's longer than 15.000 characters.")
            self.update_status("Ready")

    
    

@final
class ToolTip(object):
    """
    A class for creating tooltips that appear on hover. Code is mostly from StackOverflow :P
    """
    def __init__(self, widget: Widget, tooltip: str, interval: int = 1000, length: int = 400):
        self.widget = widget
        self.interval = interval
        self.wraplength = length
        # self.text = tooltip
        # self.widget.bind("<Enter>", self.enter)
        # self.widget.bind("<Leave>", self.leave)
        # self.widget.bind("<ButtonPress>", self.leave)
        self.id = None
        self.tw = None

        self.speed = 10
    
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    def enter(self, event=None):
        self.schedule()
    def leave(self, event=None):
        self.unschedule()
        self.hidetip()
    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.interval, self.showtip)
    def unschedule(self):
        id = self.id
        self.id = None
        if id:
            self.widget.after_cancel(id)

   
    def showtip(self, event=None):
        # Get the mouse position and determine the screen coordinates to show the tooltip
        x = self.root.winfo_pointerx() + 12
        y = self.root.winfo_pointery() + 16

        # Create a Toplevel because we can't just show a label out of nowhere in the main window with fade-in & fade-away animations
        self.tw = Toplevel(self.widget)
        self.tw.attributes("-alpha", 0)

        # Configure the tooltip for visuality
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = Label(self.tw, text=self.text,
            justify='left', background="#ffffff",
            foreground="#6f6f6f", relief='solid',
            borderwidth=1, wraplength=self.wraplength)
        label.pack(ipadx=1)

        def fade_in():
            if not self.widget is self.root.winfo_containing(self.root.winfo_pointerx(), self.root.winfo_pointery()):
                # If mouse is no longer on the widget, destroy the tooltip and unschedule the fade_in
                self.tw.destroy()
                return
            alpha = self.tw.attributes("-alpha")
            if alpha != 1:
                # Increase the transparency by 0.1 until it is fully visible
                alpha += .1
                self.tw.attributes("-alpha", alpha)
                # Call this function again in 10 milliseconds (value of self.speed attribute)
                self.tw.after(self.speed, fade_in)
            else:
                return
        fade_in()

 
    def hidetip(self):
        if self.tw:
            # If the tooltip is still a thing (i.e. it has not been destroyed unexpectedly), start fading it away
            def fade_away():
                if self.widget is self.root.winfo_containing(self.root.winfo_pointerx(), self.root.winfo_pointery()):
                    self.tw.destroy()
                    return
                try:
                    alpha = self.tw.attributes("-alpha")
                except TclError:
                    return
                if alpha != 0:
                    # Decrease the transparency by 0.1 until it is fully invisible
                    alpha -= .1
                    self.tw.attributes("-alpha", alpha)
                    # Call this function again in 10 milliseconds (value of self.speed attribute)
                    self.tw.after(self.speed, fade_away)
                else:
                    self.tw.destroy()
            fade_away()

@final
class ScrolledText(Text):
    """
    A Tkinter text widget with a scrollbar next to it. Code is taken from Tkinter's source code.
    """
  
    def __init__(self, master: Tk | Frame | LabelFrame, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None

        # Implement the scrollbar
        self.frame = Frame(master)
        self.vbar = Scrollbar(self.frame)
        self.vbar.pack(side=RIGHT, fill=Y)
        kwargs.update({'yscrollcommand': self.vbar.set})
        super().__init__(self.frame, *args, **kwargs)
        self.pack(side=LEFT, fill=BOTH, expand=YES)
        self.vbar['command'] = self.yview
        text_meths = vars(Text).keys()
        methods = vars(Pack).keys() | vars(Grid).keys() | vars(Place).keys()
        methods = methods.difference(text_meths)

        for m in methods:
            if m[0] != '_' and m != 'config' and m != 'configure':
                setattr(self, m, getattr(self.frame, m))

        # Implement textvariable
        if self._textvariable is not None:
            self.insert("1.0", self._textvariable.get())
        self.tk.eval("""
        proc widget_proxy {widget widget_command args} {

            set result [uplevel [linsert $args 0 $widget_command]]

            if {([lindex $args 0] in {insert replace delete})} {
                event generate $widget <<Change>> -when tail
            }

            return $result
        }""")
        self.tk.eval('''
            rename {widget} _{widget}
            interp alias {{}} ::{widget} {{}} widget_proxy {widget} _{widget}
        '''.format(widget=str(Text.__str__(self))))
        self.bind("<<Change>>", self._on_widget_change)

        if self._textvariable is not None:
            self._textvariable.trace("wu", self._on_var_change)

        # Create the tooltip object for the widget if a string for tooltip was specified (rather than None)
        # if tooltip is not None:
        #     self.toolTip = ToolTip(widget=self, tooltip=tooltip)
            
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @multipledispatch.dispatch(str)
    def replace(self, chars: str):
        """
        Method to replace the text in the widget entirely with the given string
        """
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    @multipledispatch.dispatch(str, str, str)
    def replace(self, chars: str, start_index: str, end_index: str):
        """
        Text class' original replace method in case the user (me) wants to replace a range of text
        """
        self.tk.call(self._w, 'replace', start_index, end_index, chars)

  
    def clear(self):
        """
        Method to clear all the text in the widget
        """
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.configure(state=old_val)

    
    def _on_var_change(self, *args):
        text_current = self.get("1.0", "end-1c")
        var_current = self._textvariable.get()
        if text_current != var_current:
            self.delete("1.0", "end")
            self.insert("1.0", var_current)

    def _on_widget_change(self, event=None):
        if self._textvariable is not None:
            self._textvariable.set(self.get("1.0", "end-1c"))

    def __str__(self):
        return str(self.frame)

@final
class Text(Text):
    
    def __init__(self, master: Tk | Frame | LabelFrame, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None

        super().__init__(master, *args, **kwargs)

        # Implement textvariable
        if self._textvariable is not None:
            self.insert("1.0", self._textvariable.get())
        self.tk.eval("""
        proc widget_proxy {widget widget_command args} {

            set result [uplevel [linsert $args 0 $widget_command]]

            if {([lindex $args 0] in {insert replace delete})} {
                event generate $widget <<Change>> -when tail
            }

            return $result
        }""")
        self.tk.eval('''
            rename {widget} _{widget}
            interp alias {{}} ::{widget} {{}} widget_proxy {widget} _{widget}
        '''.format(widget=str(self)))
        self.bind("<<Change>>", self._on_widget_change)

        if self._textvariable is not None:
            self._textvariable.trace("wu", self._on_var_change)
        
        # Create the tooltip object for the widget if a string for tooltip was specified (rather than None)
        

    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @multipledispatch.dispatch(str)
    def replace(self, chars: str):
        """
        Method to replace the text in the widget entirely with the given string
        """
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    @multipledispatch.dispatch(str, str, str)
    def replace(self, chars: str, start_index: str, end_index: str):
        """
        Text class' original replace method in case the user (me) wants to replace a range of text
        """
        self.tk.call(self._w, 'replace', start_index, end_index, chars)

   
    def clear(self):
        """
        Method to clear all the text in the widget
        """
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.configure(state=old_val)

    def _on_var_change(self, *args):
        text_current = self.get("1.0", "end-1c")
        var_current = self._textvariable.get()
        if text_current != var_current:
            self.delete("1.0", "end")
            self.insert("1.0", var_current)

    def _on_widget_change(self, event=None):
        if self._textvariable is not None:
            self._textvariable.set(self.get("1.0", "end-1c"))

class Notebook(Notebook):
  
    def __init__(self, master: Tk | Frame | LabelFrame, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        # self.bind("<<NotebookTabChanged>>", lambda _: self.on_tab_change())
        self.__history: Optional[list] = list()

    @property
    def last_tab(self) -> Optional[int]:
        """
        Property to get the index of the last tab that was selected in case an
        error occures while switching to a tab that downloads data from web and
        the program must return to the last tab
        """
        try:
            # Try to get the lastly indexed element from the history
            return self.__history[-1]
        except IndexError:
            if len(self.__history):
                return self.__history[0]
            else:
                return None

    
class Widget(Widget):
    """
    Base-class for all the Tkinter widgets except Text and ScrolledText widgets in order to implement tooltips easily
    """
    def __init__(self, master: Tk | Frame | LabelFrame, *args, **kwargs):
        super().__init__(master, *args, **kwargs)

        

# Multiply inherit all the widgets from the Widget class and the original Tkinter widgets in order to add tooltips to them

@final
class Entry(Widget, Entry):
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    def replace(self, string: str):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete(0, END)
        self.insert(0, string)
        self.configure(state=old_val)

    def clear(self):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete(0, END)
        self.configure(state=old_val)

@final
class Button(Widget, Button): ...

@final
class Label(Widget, Label): ...

@final
class Radiobutton(Widget, Radiobutton): ...

@final
class Checkbutton(Widget, Checkbutton): ...

@final
class Interface(Tk):
    """
    Main class for the user interface
    """
   
    def __init__(self):
        super().__init__()

        # Load either the "vista" theme (which is the default theme in Windows) or the "arc" theme depending on the operating system
        
       
        self.theme = ThemedStyle(self, gif_override=True)
        self.theme.set_theme("vista" if os.name == "nt" else "arc")

        # Create all the variables used by widgets
        self.__initialize_vars()

        # Hide the window till all the widgets are placed
        self.withdraw()

        self.height = 580
        self.width = 800
        

        # Shape the window and set the title
        self.wm_title(f"{__title__}")
        self.wm_geometry(f"{self.width}x{self.height}")
        self.wm_resizable(width=False, height=False)
        self.wm_minsize(width = self.width, height = self.height)
        self.wm_maxsize(width = self.width, height = self.height)
        # Load the icon if it's present in the current directory
        try:
            self.wm_iconbitmap("icon.ico")
        except TclError:
            # It’s easier to ask for forgiveness than permission
            pass

        # Initialize the helper classes
        self.crypto = Cryptography(self)
        
        self.utils = Utilities(self)
        
        self.scfs: list[dict[Callable, Callable]] = []
        # The main notebook widget
        class mainNotebook(Notebook):
            def __init__(self, master: Interface):
                super().__init__(master, width=380, height=340)
                self.root: Interface = self.master

                class encryptionFrame(Frame):
                    def __init__(self, master: mainNotebook = None, **kwargs):
                        super().__init__(master=master, **kwargs)
                        self.root: Interface = self.master.master

                        self.textEntryCheck = Radiobutton(self, text="Plain text:", value=0, variable=self.root.dataSourceVar, command=self.changeDataSource, takefocus=0)
                        self.textEntry = Entry(self, width=48, font=("Consolas", 9), state=NORMAL, takefocus=0, textvariable=self.root.textEntryVar)
                        self.textPasteButton = Button(self, text="Paste",  width=14, state=NORMAL, command=lambda: self.textEntry.replace(str(self.root.clipboard_get()).strip()), takefocus=0)
                        self.textClearButton = Button(self, text="Clear", width=14, command=lambda: self.textEntry.delete(0, END), takefocus=0, state=DISABLED)
                        self.textEntryHideCharCheck = Checkbutton(self, text="Hide characters", variable=self.root.textEntryHideCharVar, onvalue=1, offvalue=0, command=self.changeDataEntryHideChar, takefocus=0)

                        self.fileEntryCheck = Radiobutton(self, text="File(s):", value=1, variable=self.root.dataSourceVar, takefocus=0)
                        self.fileValidityLabel = Label(self, text="Validity: [Blank]", cursor="hand2", foreground="gray")
                        self.fileEntry = Entry(self, width=48, font=("Consolas", 9), state=NORMAL, takefocus=0, textvariable=self.root.fileEntryVar)
                        self.fileBrowseButton = Button(self, text="Browse...", width=14, state=NORMAL, command=self.fileEntryBrowse, takefocus=0)
                        self.fileClearButton = Button(self, text="Clear", width=14, state=NORMAL, command=lambda: self.fileEntry.delete(0, END), takefocus=0)
                        self.writeFileContentCheck = Checkbutton(self, text="Write encrypted data", variable=self.root.encryptWriteFileContentVar, state=NORMAL, takefocus=0)

                        self.root.textEntryVar.trace("w", self.textEntryCallback)
                        self.root.fileEntryVar.trace("w", self.fileEntryCallback)
                        
                        # self.fileValidityLabel.bind("<Button-1>", self.showDebug)
                        self.asymmetricFrameCheck = Radiobutton(self, text="Asymmetric", value=2,  takefocus=0)
                        self.symmetricFrameCheck = Radiobutton(self, text="Symmetric", value=3,   takefocus=0)
                        self.textEntryCheck.place(x=8, y=2)
                        self.textEntry.place(x=24, y=22)
                        self.textPasteButton.place(x=23, y=49)
                        self.textClearButton.place(x=124, y=49)

                        self.fileEntryCheck.place(x=8, y=76)
                        self.fileValidityLabel.place(x=63, y=77)
                        self.fileEntry.place(x=24, y=96)
                        self.fileBrowseButton.place(x=23, y=123)
                        self.fileClearButton.place(x=124, y=123)
                        self.writeFileContentCheck.place(x=236, y=124)

                        class algorithmSelect(Notebook):
                            def __init__(self, master: encryptionFrame):
                                super().__init__(master, width=355, height=290, takefocus=0)
                                self.root: encryptionFrame = self.master.master.master

                                class symmetricEncryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root: Interface = self.master.master.master.master

                                        self.generateRandomKeyCheck = Radiobutton(self, text="Generate a random key",  value=0, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)
                                        self.root.selected_algorithm="ss"
                                        self.AESAlgorithmCheck = Radiobutton(self, text="AES (Advanced Encryption Standard)",  value=0, variable=self.root.generateAlgorithmSelection, command=self.master.master.changeAlgorithmSelection, takefocus=0)
                                        self.AES128Check = Radiobutton(self, text="AES-128 Key", value=128, variable=self.root.generateRandomAESVar, takefocus=0)
                                        self.AES192Check = Radiobutton(self, text="AES-192 Key", value=192, variable=self.root.generateRandomAESVar, takefocus=0)
                                        self.AES256Check = Radiobutton(self, text="AES-256 Key", value=256, variable=self.root.generateRandomAESVar, takefocus=0)

                                        self.DESAlgorithmCheck = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.generateAlgorithmSelection, command=self.master.master.changeAlgorithmSelection, takefocus=0)
                                        self.DES128Check = Radiobutton(self, text="3DES-128 Key", value=128, state=DISABLED, variable=self.root.generateRandomDESVar, takefocus=0)
                                        self.DES192Check = Radiobutton(self, text="3DES-192 Key", value=192, state=DISABLED, variable=self.root.generateRandomDESVar, takefocus=0)

                                        self.selectKeyCheck = Radiobutton(self, text="Use this key:", value=1, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)
                                        self.keyEntry = Entry(self, width=46, font=("Consolas",9), state=DISABLED, textvariable=self.root.keyEntryVar, takefocus=0)
                                        self.keyValidityStatusLabel = Label(self, text="Validity: [Blank]", foreground="gray", takefocus=0)
                                        self.keyEntryHideCharCheck = Checkbutton(self, text="Hide characters", onvalue=1, offvalue=0, variable=self.root.keyEntryHideCharVar, command=self.keyEntryHideCharChange, state=DISABLED, takefocus=0)
                                        self.keyBrowseButton = Button(self, text="Browse key file...", width=21, state=DISABLED, command=lambda: self.root.crypto.get_key(self.root, self.keyEntry), takefocus=0)
                                        self.keyPasteButton = Button(self, text="Paste", width=13, state=DISABLED, command=lambda: self.keyEntry.replace(self.root.clipboard_get()), takefocus=0)
                                        self.keyClearButton = Button(self, text="Clear", width=13, state=DISABLED, command=lambda: self.keyEntry.clear(), takefocus=0)
                                        self.keyEnteredAlgAES = Radiobutton(self, text="AES (Advanced Encryption Standard)", value=0, variable=self.root.entryAlgorithmSelection, command=self.master.master.limitKeyEntry, state=DISABLED, takefocus=0)
                                        self.keyEnteredAlgDES = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.entryAlgorithmSelection, command=self.master.master.limitKeyEntry, state=DISABLED, takefocus=0)

                                        self.root.keyEntryVar.trace("w", self.master.master.limitKeyEntry)

                                        self.generateRandomKeyCheck.place(x=5, y=5)
                                        self.AESAlgorithmCheck.place(x=16, y=25)
                                        self.AES128Check.place(x=27, y=44)
                                        self.AES192Check.place(x=27, y=63)
                                        self.AES256Check.place(x=27, y=82)
                                        self.DESAlgorithmCheck.place(x=16, y=101)
                                        self.DES128Check.place(x=27, y=120)
                                        self.DES192Check.place(x=27, y=139)
                                        self.keyEntry.place(x=18, y=181)
                                        self.keyValidityStatusLabel.place(x=92, y=159)
                                        self.keyClearButton.place(x=114, y=207)
                                        self.keyPasteButton.place(x=17, y=207)
                                        self.keyBrowseButton.place(x=211, y=207)
                                        self.keyEntryHideCharCheck.place(x=244, y=158)
                                        self.selectKeyCheck.place(x=5, y=158)
                                        self.keyEnteredAlgAES.place(x=16, y=235)
                                        self.keyEnteredAlgDES.place(x=16, y=254)

                                    def keyEntryHideCharChange(self):
                                        self.keyEntry.configure(show="●" if self.root.keyEntryHideCharVar.get() else "")

                                
                                    
                        
                                self.symmetricEncryption = symmetricEncryption(self)

                                self.add(self.symmetricEncryption, text="Symmetric Key Encryption")
                                
                    
                            
                        self.algorithmSelect = algorithmSelect(self)
                        
                        self.encryptButton = Button(self, text="Encrypt", width=22, command=self.root.crypto.encrypt, takefocus=0)

                        self.algorithmSelect.place(x=10, y=155)
                        self.encryptButton.place(x=9, y=480)

                        class outputFrame(LabelFrame):
                            def __init__(self, master: Frame):
                                super().__init__(master, text="Output", height=502, width=403, takefocus=0)
                                self.root: Interface = self.master.master.master

                                self.outputText = ScrolledText(self, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, textvariable=self.root.outputVar, highlightcolor="#cccccc")
                                self.AESKeyText = Text(self, width=54, height=1, state=DISABLED, font=("Consolas",9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, textvariable=self.root.AESKeyVar, highlightcolor="#cccccc")
                                
                                self.AESKeyLabel = Label(self, text="AES/3DES Key:", takefocus=0)
                                

                                self.root.outputVar.trace("w", self.outputTextCallback)
                                self.root.AESKeyVar.trace("w", self.AESKeyTextCallback)

                                self.copyOutputButton = Button(self, text = "Copy", width=10, command=lambda: self.root.clipboard_set(self.outputText.get("1.0", END)), state=DISABLED, takefocus=0)
                                self.clearOutputButton = Button(self, text = "Clear", width=10, command=lambda: self.outputText.clear(), state=DISABLED, takefocus=0)
                                self.saveOutputButton = Button(self, width=15, text="Save as...", command=self.saveOutput, state=DISABLED, takefocus=0)
                                self.copyAESKeyButton = Button(self, width = 10, text="Copy", command=lambda: self.root.clipboard_set(self.AESKeyText.get("1.0", END)), state=DISABLED, takefocus=0)
                                self.clearAESKeyButton = Button(self, width = 10, text="Clear", command=lambda: self.AESKeyText.clear(), state=DISABLED, takefocus=0)
                                self.saveAESKeyButton = Button(self, width=15, text="Save as...", command=lambda: self.root.crypto.save_key(self.root.AESKeyVar.get(), self.root), state=DISABLED, takefocus=0)
                                
                               
                                self.outputText.place(x=9, y=5)
                                self.AESKeyText.place(x=9, y=145)
                                
                                self.AESKeyLabel.place(x=8, y=125)
                                
                                self.copyOutputButton.place(x=8, y=100)
                                self.clearOutputButton.place(x=85, y=100)
                                self.saveOutputButton.place(x=162, y=100)
                                self.copyAESKeyButton.place(x=8, y=170)
                                self.clearAESKeyButton.place(x=85, y=170)
                                self.saveAESKeyButton.place(x=162, y=170)
                                

                            def saveOutput(self):
                                path = filedialog.asksaveasfilename(title="Save encrypted data", initialfile=os.path.split(self.root.lastEncryptedFile)[1] if self.root.lastEncryptedFile is not None else "Encrypted Text.txt", filetypes=[("All files", "*.*")], defaultextension="*.txt")
                                if ''.join(path.split()) == '':
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.outputVar.get())

                            def saveRSAPublic(self):
                                path = filedialog.asksaveasfilename(title="Save public key", initialfile="Public Key.txt", filetypes=[("Text document", "*.txt"), ("All files", "*.*")], defaultextension="*.txt")
                                if ''.join(path.split()) == '':
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.RSAPublicVar.get())

                            def saveRSAPrivate(self):
                                path = filedialog.asksaveasfilename(title="Save private key", initialfile="Private Key.txt", filetypes=[("Text document", "*.txt"), ("All files", "*.*")], defaultextension="*.txt")
                                if ''.join(path.split()) == '':
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.RSAPrivateVar.get())

                            def outputTextCallback(self, *args, **kwargs):
                                if self.root.outputVar.get() == "":
                                    self.outputText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
                                    self.clearOutputButton.configure(state=DISABLED)
                                    self.copyOutputButton.configure(state=DISABLED)
                                    self.saveOutputButton.configure(state=DISABLED)
                                else:
                                    self.outputText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a")
                                    self.clearOutputButton.configure(state=NORMAL)
                                    self.copyOutputButton.configure(state=NORMAL)
                                    self.saveOutputButton.configure(state=NORMAL)

                            def AESKeyTextCallback(self, *args, **kwargs):
                                if self.root.AESKeyVar.get() == "":
                                    self.AESKeyText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
                                    self.clearAESKeyButton.configure(state=DISABLED)
                                    self.copyAESKeyButton.configure(state=DISABLED)
                                    self.saveAESKeyButton.configure(state=DISABLED)
                                else:
                                    self.AESKeyText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a")
                                    self.clearAESKeyButton.configure(state=NORMAL)
                                    self.copyAESKeyButton.configure(state=NORMAL)
                                    self.saveAESKeyButton.configure(state=NORMAL)

                            

                        self.outputFrame = outputFrame(self)
                        self.outputFrame.place(x=377, y=4)
                    
                    @state_control_function(self)
                    def changeDataEntryHideChar(self):
                        self.textEntry.configure(show="●" if bool(self.root.textEntryHideCharVar.get()) else "")

                    def changeEnterKeySectionState(self, state = DISABLED):
                        self.algorithmSelect.symmetricEncryption.keyEntry.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyEntryHideCharCheck.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyPasteButton.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyBrowseButton.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyEnteredAlgDES.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyEnteredAlgAES.configure(state=state)
                        self.limitKeyEntry()

                    def changeGenerateKeySectionState(self, state = NORMAL):
                        self.algorithmSelect.symmetricEncryption.AESAlgorithmCheck.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.DESAlgorithmCheck.configure(state=state)

                    def changeAESState(self, state = NORMAL):
                        self.algorithmSelect.symmetricEncryption.AES128Check.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.AES192Check.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.AES256Check.configure(state=state)
                    
                    def changeDESState(self, state = DISABLED):
                        self.algorithmSelect.symmetricEncryption.DES128Check.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.DES192Check.configure(state=state)

                    @state_control_function(self)
                    def changeAlgorithmSelection(self):
                        self.changeAESState(state = DISABLED if bool(self.root.generateAlgorithmSelection.get()) else NORMAL)
                        self.changeDESState(state = NORMAL if bool(self.root.generateAlgorithmSelection.get()) else DISABLED)

                    @state_control_function(self)
                    def changeSourceSelection(self):
                        self.changeGenerateKeySectionState(state = DISABLED if bool(self.root.keySourceSelection.get()) else NORMAL)
                        self.changeAESState(state = DISABLED if bool(self.root.keySourceSelection.get()) else DISABLED if bool(self.root.generateAlgorithmSelection.get()) else NORMAL)
                        self.changeDESState(state = DISABLED if bool(self.root.keySourceSelection.get()) else NORMAL if bool(self.root.generateAlgorithmSelection.get()) else DISABLED)
                        self.changeEnterKeySectionState(state = NORMAL if bool(self.root.keySourceSelection.get()) else DISABLED)

                        if not bool(self.root.keySourceSelection.get()):
                            self.encryptButton.configure(state=NORMAL)
                            self.fileEntryCallback()
                        elif bool(self.root.keySourceSelection.get()) and (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and os.path.isfile(self.fileEntry.get()))):
                            self.encryptButton.configure(state=NORMAL)
                            self.limitKeyEntry()

                        if not bool(self.root.keySourceSelection.get()):
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="gray")
                        else:
                            colors = {
                                "Validity: Valid": "green",
                                "Validity: Invalid": "red",
                                "Validity: [Blank]": "gray"
                            }
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground=colors[" ".join(self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel["text"].split()[:2])])

                    def limitKeyEntry(self, *args, **kwargs) -> None:
                        global value
                        if len(self.master.master.keyEntryVar.get()) > 32:
                            # If the entry contains 33 characters (prolly caused by a bug in Tkinter), remove the last character
                            self.master.master.keyEntryVar.set(self.master.master.keyEntryVar.get()[:32])
                        value = self.master.master.keyEntryVar.get()
                        if ''.join(str(self.master.master.keyEntryVar.get()).split()) == "":
                            # If the entry is empty, gray out the encrypt and clear buttons, and update the status text
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="gray", text="Validity: [Blank]")
                            self.encryptButton.configure(state=DISABLED)
                            self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=DISABLED)
                        else:
                            # If the entry actually contains something, go ahead
                            self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=NORMAL if bool(self.root.keySourceSelection.get()) else DISABLED)
                            if not bool(self.master.master.keySourceSelection.get()):
                                cond = bool(self.master.master.generateAlgorithmSelection.get())
                            else:
                                cond = bool(self.master.master.entryAlgorithmSelection.get())
                            iv = get_random_bytes(AES.block_size if not cond else DES3.block_size)
                            try:
                                if not cond:
                                    AES.new(bytes(value, 'utf-8'), mode=AES.MODE_OFB, iv=iv)
                                else:
                                    DES3.new(bytes(value, 'utf-8'), mode=DES3.MODE_OFB, iv=iv)
                            except:
                                if not len(value) in [16, 24, 32]:
                                    self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="red", text=f"Validity: Invalid Key")
                                else:
                                    self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="red", text=f"Validity: Invalid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")
                                if "3DES-256" in self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel["text"]:
                                    self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(text="Validity: Invalid Key")
                                self.encryptButton.configure(state=DISABLED)
                            else:
                                self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="green", text=f"Validity: Valid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")
                                self.encryptButton.configure(state=NORMAL if (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and os.path.isfile(self.fileEntry.get()))) else DISABLED)
                                self.fileEntryCallback()

                    @state_control_function(self)
                    def changeDataSource(self):
                        if bool(self.master.master.dataSourceVar.get()):
                            self.writeFileContentCheck.configure(state=NORMAL)
                            self.textEntry.configure(state=DISABLED)
                            self.textEntryHideCharCheck.configure(state=DISABLED)
                            self.textClearButton.configure(state=DISABLED)
                            self.textPasteButton.configure(state=DISABLED)

                            self.fileEntry.configure(state=NORMAL)
                            self.fileBrowseButton.configure(state=NORMAL)
                            if (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and os.path.isfile(self.fileEntry.get()))):
                                self.fileClearButton.configure(state=NORMAL)
                                self.encryptButton.configure(state=NORMAL)
                            else:
                                self.fileClearButton.configure(state=DISABLED)
                                self.encryptButton.configure(state=DISABLED)
                            self.root.mainNotebook.encryptionFrame.algorithmSelect.tab(1, state=DISABLED)
                        else:
                            self.writeFileContentCheck.configure(state=DISABLED)
                            self.textEntry.configure(state=NORMAL)
                            if self.master.master.textEntryVar.get() != "":
                                self.textClearButton.configure(state=NORMAL)
                            else:
                                self.textClearButton.configure(state=DISABLED)
                            self.textEntryHideCharCheck.configure(state=NORMAL)
                            self.textPasteButton.configure(state=NORMAL)

                            self.fileEntry.configure(state=DISABLED)
                            self.fileBrowseButton.configure(state=DISABLED)
                            self.fileClearButton.configure(state=DISABLED)
                            self.encryptButton.configure(state=NORMAL)
                            # self.root.mainNotebook.encryptionFrame.algorithmSelect.tab(1, state=NORMAL)
                            if bool(self.master.master.keySourceSelection.get()):
                                self.limitKeyEntry()
                        if not bool(self.master.master.dataSourceVar.get()):
                            not self.fileValidityLabel["foreground"] in ["gray", "grey"] and not "[Blank]" in self.fileValidityLabel["text"]
                            if not self.fileValidityLabel["foreground"] in ["gray", "grey"] and not "[Blank]" in self.fileValidityLabel["text"]:
                                self.fileValidityStatusColor = self.fileValidityLabel["foreground"]
                            self.fileValidityLabel.configure(foreground="gray")
                        else:
                            try:
                                self.fileValidityLabel.configure(foreground=self.fileValidityStatusColor)
                            except AttributeError:
                                self.fileValidityLabel.configure(foreground="gray")

                    def fileEntryBrowse(self):
                        global filePath
                        filePath = filedialog.askopenfilenames(title = "Open a file to encrypt", filetypes=[("All files", "*.*")])

                        if not filePath:
                            return
                        self.fileEntry.replace(' | '.join(filePath))

                    def textEntryCallback(self, *args, **kwargs):
                        self.textClearButton.configure(state=DISABLED if self.master.master.textEntryVar.get() == "" else NORMAL)
                    
                    def fileEntryCallback(self, *args, **kwargs):
                        self.fileClearButton.configure(state=DISABLED if ''.join(self.fileEntry.get().split()) != '' else NORMAL)
                        if ''.join(self.fileEntry.get().split()) != '':
                            all_valid = all([os.path.isfile(filename) for filename in [filename.lstrip() for filename in self.fileEntry.get().split('|') if ''.join(filename.split()) != '']])
                            self.fileValidityLabel.configure(**{"text": f"Selection: {len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != ''])} file{'s' if len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != '']) != 1 else ''} selected", "foreground": "green" if all_valid else "red"})
                        else:
                            self.fileValidityLabel.configure(text="Selection: [Blank]", foreground="gray")
                        self.encryptButton.configure(state=DISABLED if ''.join(self.fileEntry.get().split()) == '' else NORMAL if (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and all_valid and (not bool(self.root.keySourceSelection.get()) or (bool(self.root.keySourceSelection.get()) and ''.join(self.root.mainNotebook.encryptionFrame.algorithmSelect.symmetricEncryption.keyEntry.get().split()) != '')))) else DISABLED)
                    


                class decryptionFrame(Frame):
                    def __init__(self, master: Notebook = None, **kwargs):
                        super().__init__(master=master, **kwargs)
                        self.root: Interface = self.master.master

                        self.textDecryptRadio = Radiobutton(self, text = "Cipher text:", value=0, variable=self.root.decryptSourceVar, command=self.changeDecryptSource, takefocus=0)
                        self.textDecryptValidityLabel = Label(self, text="Validity: [Blank]", foreground="gray")
                        self.textDecryptEntry = ScrolledText(self, width=105, height=5, font=("Consolas", 9), textvariable=self.root.textDecryptVar, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                        self.textDecryptPasteButton = Button(self, width=15, text="Paste", command=lambda: self.textDecryptEntry.replace(self.root.clipboard_get()), takefocus=0)
                        self.textDecryptClearButton = Button(self, width=15, text="Clear", command=lambda: self.textDecryptEntry.delete("1.0", END), takefocus=0, state=DISABLED)

                        self.fileDecryptRadio = Radiobutton(self, text = "File(s):", value=1, variable=self.root.decryptSourceVar, command=self.changeDecryptSource, takefocus=0)
                        self.fileDecryptEntry = Entry(self, width=107, font=("Consolas", 9), textvariable=self.root.fileDecryptVar, state=DISABLED, takefocus=0)
                        self.fileDecryptBrowseButton = Button(self, width=15, text="Browse...", state=DISABLED, command=self.decryptBrowseFile, takefocus=0)
                        self.fileDecryptClearButton = Button(self, width=15, text="Clear", state=DISABLED, command=lambda: self.fileDecryptEntry.delete(0, END), takefocus=0)

                        self.textDecryptRadio.place(x=8, y=2)
                        self.textDecryptValidityLabel.place(x=92, y=3)
                        self.textDecryptEntry.place(x=24, y=24)
                        self.textDecryptPasteButton.place(x=23, y=107)
                        self.textDecryptClearButton.place(x=130, y=107)

                        self.fileDecryptRadio.place(x=8, y=132)
                        self.fileDecryptEntry.place(x=24, y=153)
                        self.fileDecryptBrowseButton.place(x=23, y=182)
                        self.fileDecryptClearButton.place(x=130, y=182)

                        class algorithmSelect(Notebook):
                            def __init__(self, master: encryptionFrame):
                                super().__init__(master, width=764, height=160, takefocus=0)
                                self.root: encryptionFrame = self.master.master.master

                                class symmetricDecryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root: Interface = self.master.master.master.master

                                        class decryptAlgorithmFrame(LabelFrame):
                                            def __init__(self, master: symmetricDecryption, **kwargs):
                                                super().__init__(master, **kwargs)
                                                self.root: Interface = self.master.master.master.master.master

                                                self.decryptAESCheck = Radiobutton(self, text="AES (Advanced Encryption Standard)", value=0, variable=self.root.decryptAlgorithmVar, takefocus=0)
                                                self.decryptDESCheck = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.decryptAlgorithmVar, takefocus=0)

                                                self.decryptAESCheck.place(x=5, y=0)
                                                self.decryptDESCheck.place(x=5, y=19)

                                        self.decryptAlgorithmFrame = decryptAlgorithmFrame(self, text="Select algorithm", height=63, width=749, takefocus=0)
                                        self.decryptAlgorithmFrame.place(x=8, y=2)

                                        class decryptKeyFrame(LabelFrame):
                                            def __init__(self, master: symmetricDecryption, **kwargs):
                                                super().__init__(master, **kwargs)
                                                self.root: Interface = self.master.master.master.master.master

                                                self.decryptKeyEntry = Entry(self, width=103, font=("Consolas", 9), textvariable=self.root.decryptKeyVar, takefocus=0)
                                                self.decryptKeyBrowseButton = Button(self, width=21, text="Browse key file...", command=lambda: self.root.crypto.get_key(self.root, self.decryptKeyEntry), takefocus=0)
                                                self.decryptKeyPasteButton = Button(self, width=15, text="Paste", takefocus=0, command=lambda: self.decryptKeyEntry.replace(self.root.clipboard_get()))
                                                self.decryptKeyClearButton = Button(self, width=15, text="Clear", takefocus=0, command=lambda: self.decryptKeyEntry.delete(0, END), state=DISABLED)

                                                self.decryptKeyEntry.place(x=9, y=3)
                                                self.decryptKeyBrowseButton.place(x=601, y=30)
                                                self.decryptKeyPasteButton.place(x=8, y=30)
                                                self.decryptKeyClearButton.place(x=115, y=30)

                                                self.root.decryptKeyVar.trace("w", self.decryptLimitKeyEntry)
                                                self.root.decryptOutputVar.trace("w", self.decryptOutputCallback)

                                            def decryptLimitKeyEntry(self, *args, **kwargs):
                                                global value
                                                if len(self.root.decryptKeyVar.get()) > 32:
                                                    self.root.decryptKeyVar.set(self.root.decryptKeyVar.get()[:32])
                                                value = self.root.decryptKeyVar.get()
                                                if ''.join(str(self.root.decryptKeyVar.get()).split()) == "":
                                                    self.decryptKeyClearButton.configure(state=DISABLED)
                                                else:
                                                    self.decryptKeyClearButton.configure(state=NORMAL)
                                                if len(value) == 0:
                                                    self.master.master.master.decryptButton.configure(state=DISABLED)
                                                else:
                                                    cond = bool(self.root.decryptAlgorithmVar.get())
                                                    iv = get_random_bytes(AES.block_size if not cond else DES3.block_size)
                                                    try:
                                                        if not cond:
                                                            AES.new(bytes(value, 'utf-8'), mode=AES.MODE_OFB, iv=iv)
                                                        else:
                                                            DES3.new(bytes(value, 'utf-8'), mode=DES3.MODE_OFB, iv=iv)
                                                    except:
                                                        self.master.master.master.decryptButton.configure(state=DISABLED)
                                                    else:
                                                        if not bool(self.root.decryptSourceVar.get()):
                                                            try:
                                                                if ''.join(self.master.master.master.textDecryptEntry.get("1.0", END).split()) != "" and base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.master.master.master.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.master.master.master.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                                                    self.master.master.master.decryptButton.configure(state=NORMAL)
                                                                else:
                                                                    self.master.master.master.decryptButton.configure(state=DISABLED)
                                                            except binascii.Error:
                                                                self.master.master.master.decryptButton.configure(state=DISABLED)
                                                        else:
                                                            if self.master.master.master.fileDecryptCallback():
                                                                self.master.master.master.decryptButton.configure(state=NORMAL)
                                                            else:
                                                                self.master.master.master.decryptButton.configure(state=DISABLED)

                                            def decryptOutputCallback(self, *args, **kwargs):
                                                if not ''.join(str(self.root.decryptOutputVar.get()).split()) == "":
                                                    self.master.master.master.decryptClearButton.configure(state=NORMAL)
                                                    self.master.master.master.decryptCopyButton.configure(state=NORMAL)
                                                    self.master.master.master.decryptSaveButton.configure(state=NORMAL)
                                                else:
                                                    self.master.master.master.decryptClearButton.configure(state=DISABLED)
                                                    self.master.master.master.decryptCopyButton.configure(state=DISABLED)
                                                    self.master.master.master.decryptSaveButton.configure(state=DISABLED)

                                        self.decryptKeyFrame = decryptKeyFrame(self, text="Enter encryption key", height=84, width=749, takefocus=0)
                                        self.decryptKeyFrame.place(x=8, y=68)
                                        self.decryptKeyValidity = Label(self, text="Validity: [Blank]", foreground="gray")

                                # class asymmetricDecryption(Frame):
                                #     def __init__(self, master: Notebook, **kwargs):
                                #         super().__init__(master, **kwargs)
                                #         self.root: Interface = self.master.master.master.master

                                        
                                self.symmetricDecryption = symmetricDecryption(self)
                                # self.asymmetricDecryption = asymmetricDecryption(self)

                                self.add(self.symmetricDecryption, text="Symmetric Key Decryption")
                                # self.add(self.asymmetricDecryption, text="Asymmetric Key Decryption")

                        self.algorithmSelect = algorithmSelect(self)
                        self.algorithmSelect.place(x=10, y=215)
                        
                        self.decryptButton = Button(self, width=22, text="Decrypt", command=self.root.crypto.decrypt, takefocus=0)
                        self.decryptOutputFrame = LabelFrame(self, text="Decrypted text", height=84, width=766, takefocus=0)
                        self.decryptOutputText = Entry(self.decryptOutputFrame, width=105, font=("Consolas", 9), textvariable=self.master.master.decryptOutputVar, takefocus=0)
                        self.decryptCopyButton = Button(self.decryptOutputFrame, text="Copy", width=17, command=lambda: self.root.clipboard_set(self.root.self.lastDecryptionResult), takefocus=0)
                        self.decryptClearButton = Button(self.decryptOutputFrame, text="Clear", width=17, command=lambda: self.decryptOutputText.clear(), takefocus=0)
                        self.decryptSaveButton = Button(self.decryptOutputFrame, text="Save as...", width=20, takefocus=0)

                        self.root.textDecryptVar.trace("w", self.textDecryptCallback)
                        self.root.fileDecryptVar.trace("w", self.fileDecryptCallback)
                        
                        self.decryptButton.place(x=9, y=406)
                        self.decryptOutputFrame.place(x=10, y=435)
                        self.decryptOutputText.place(x=10, y=3)
                        self.decryptCopyButton.place(x=9, y=30)
                        self.decryptClearButton.place(x=128, y=30)
                        self.decryptSaveButton.place(x=622, y=30)

                    @state_control_function(self)
                    def changeDecryptSource(self):
                        if not bool(self.root.decryptSourceVar.get()):
                            self.textDecryptEntry.configure(state=NORMAL, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a", foreground="black")
                            self.textDecryptPasteButton.configure(state=NORMAL)
                            self.textDecryptClearButton.configure(state=NORMAL)
                            self.fileDecryptEntry.configure(state=NORMAL)
                            self.fileDecryptBrowseButton.configure(state=NORMAL)
                            self.fileDecryptClearButton.configure(state=NORMAL)
                            if not ''.join(str(self.textDecryptEntry.get("1.0", END)).split()) == "":
                                try:
                                    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                        self.textDecryptValidityLabel.configure(text="Validity: Valid base64 encoded data", foreground="green")
                                        self.decryptButton.configure(state=NORMAL if ''.join(self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptKeyEntry.get().split()) != '' else DISABLED)
                                    else:
                                        self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                                        self.decryptButton.configure(state=DISABLED)
                                except:
                                    self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                                    self.decryptButton.configure(state=DISABLED)
                            else:
                                self.textDecryptValidityLabel.configure(text="Validity: [Blank]", foreground="gray")
                                self.decryptButton.configure(state=DISABLED)
                        else:
                            self.textDecryptEntry.configure(state=DISABLED, bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc", foreground="gray")
                            self.textDecryptPasteButton.configure(state=DISABLED)
                            self.textDecryptClearButton.configure(state=DISABLED)
                            self.fileDecryptEntry.configure(state=NORMAL)
                            self.fileDecryptBrowseButton.configure(state=NORMAL)
                            self.fileDecryptClearButton.configure(state=NORMAL)
                            if os.path.isfile(self.fileDecryptEntry.get()):
                                self.decryptButton.configure(state=NORMAL if ''.join(self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptKeyEntry.get().split()) != '' else DISABLED)
                            else:
                                self.decryptButton.configure(state=DISABLED)
                        self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptLimitKeyEntry()

                    def textDecryptCallback(self, *args, **kwargs):
                        if not ''.join(str(self.textDecryptEntry.get("1.0", END)).split()) == "":
                            try:
                                if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                    self.textDecryptValidityLabel.configure(text="Validity: Valid base64 encoded data", foreground="green")
                                    self.decryptButton.configure(state=NORMAL)
                                    self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptLimitKeyEntry()
                                else:
                                    self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                                    self.decryptButton.configure(state=DISABLED)
                            except binascii.Error:
                                self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                                self.decryptButton.configure(state=DISABLED)
                        else:
                            self.textDecryptValidityLabel.configure(text="Validity: [Blank]", foreground="gray")
                            self.decryptButton.configure(state=DISABLED)

                    def fileDecryptCallback(self, *args, **kwargs):
                        self.fileDecryptClearButton.configure(state=DISABLED if ''.join(self.fileDecryptEntry.get().split()) != '' else NORMAL)
                        if ''.join(self.fileDecryptEntry.get().split()) != '':
                            all_valid = all([os.path.isfile(filename) for filename in [filename.lstrip() for filename in self.fileDecryptEntry.get().split('|') if ''.join(filename.split()) != '']])
                            #self.fileValidityLabel.configure(**{"text": f"Selection: {len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != ''])} file{'s' if len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != '']) != 1 else ''} selected", "foreground": "green" if all_valid else "red"})
                        else:
                            pass
                            #self.fileValidityLabel.configure(text="Selection: [Blank]", foreground="gray")
                        return_res = {
                            DISABLED: False,
                            NORMAL: True
                        }
                        state = DISABLED if ''.join(self.fileDecryptEntry.get().split()) == '' else NORMAL if (
                            not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and all_valid and (
                                ''.join(self.root.mainNotebook.decryptionFrame.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptKeyEntry.get().split()) != ''
                            ))
                        ) else DISABLED
                                
                        self.decryptButton.configure(state=state)
                        return return_res[state]

                    def decryptBrowseFile(self):
                        filePath = filedialog.askopenfilenames(title = "Open a file to decrypt", filetypes=[("All files","*.*")])
                        if not filePath:
                            return
                        self.fileDecryptEntry.replace(' | '.join(filePath))

                class miscFrame(Frame):
                    def __init__(self, master: mainNotebook = None):
                        super().__init__(master=master)
                        self.root: Interface = self.master.master

                        # self.loadingText.place(relx=.5, rely=.5, anchor=CENTER)
                        
                
                self.encryptionFrame = encryptionFrame(self)
                self.decryptionFrame = decryptionFrame(self)
                # self.miscFrame = miscFrame(self)
                # self.loggingFrame = loggingFrame(self)
                

                self.add(self.encryptionFrame, text="Encryption")
                self.add(self.decryptionFrame, text="Decryption")
                

        self.mainNotebook = mainNotebook(self)
        self.mainNotebook.pack(fill=BOTH, expand=YES, pady=4, padx=4, side=TOP)

        # This is the statusbar in the bottom of the window
        self.statusBar = TkLabel(self, text="Status: Ready", bd=1, relief=SUNKEN, anchor=W)
        self.statusBar.pack(side=BOTTOM, fill=X)

        # Ready up everything after placing all the widgets
        # self.__initialize_menu()
        # self.__initialize_protocols()
        self.__initialize_bindings()
        

        # We're ready to go now, make the window visible
        self.deiconify()
        
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    def __initialize_vars(self):
        """
        All the variables (either an instance of StringVar or IntVar) that are used by widgets are created here
        """
        self.selected_algorithm=""
        self.RSAPublicVar = StringVar()
        self.RSAPrivateVar = StringVar()
        self.showTextChar = IntVar(value=0)
        # self.showTooltip = IntVar(value=1)
        self.showInfoBox = IntVar(value=1)
        self.showWarnBox = IntVar(value=1)
        self.showErrorBox = IntVar(value=1)
        self.windowAlpha = IntVar(value=100)
        self.updateInterval = IntVar(value=1)
        self.languageVar = IntVar(value=0)
        self.themeVar = StringVar(value="vista")
        self.loggingTextVar = StringVar()
        self.loggingAutoSaveVar = IntVar(value=0)
        self.levelSelectVar = StringVar(value="INFO")
        self.alwaysOnTopVar = IntVar(value=0)

        self.generateRandomAESVar = IntVar(value=256)
        self.generateRandomDESVar = IntVar(value=192)
        self.generateRandomRSAVar = IntVar(value=2048)
        self.keySourceSelection = IntVar(value=0)
        self.generateAlgorithmSelection = IntVar(value=0)
        self.entryAlgorithmSelection = IntVar(value=0)
        self.keyEntryVar = StringVar()
        self.keyEntryHideCharVar = IntVar()

        self.dataSourceVar = IntVar(value=0)
        self.textEntryVar = StringVar()
        self.fileEntryVar = StringVar()
        self.textEntryHideCharVar = IntVar(value=0)
        self.encryptWriteFileContentVar = IntVar(value=1)
        self.decryptWriteFileContentVar = IntVar(value=1)
        self.outputVar = StringVar()
        self.AESKeyVar = StringVar()
        
        self.customRSALengthVar = IntVar()
        

        self.decryptSourceVar = IntVar(value=0)
        self.decryptAlgorithmVar = IntVar(value=0)
        self.textDecryptVar = StringVar()
        self.fileDecryptVar = StringVar()
        self.decryptKeyVar = StringVar()
        self.decryptOutputVar = StringVar()

        self.encodeOrDecodeVar = IntVar(value=0)
        self.base64InputVar = StringVar()
        self.base64OutputVar = StringVar()
        self.base64SourceVar = IntVar(value=0)
        self.base64FileEntryVar = StringVar()
        self.keyInputVar = StringVar()
        self.keyInputHideVar = IntVar(value=0)
        self.keyOutputVar = StringVar()
        self.hashCalculationSourceVar = IntVar(value=0)
        self.hashPasswordEntryVar = StringVar()
        self.hashFileEntryVar = StringVar()

        self.showProgramNameVar = IntVar(value=1)
        self.showProgramVersionVar = IntVar(value=1)
        self.showTimeVar = IntVar(value=0)
        self.showDateVar = IntVar(value=0)
        self.titlebarUpdateInterval = IntVar(value=200)
        self.autoSaveConfigVar = IntVar(value=1)

    def __initialize_bindings(self):
        """
        Method to create the bindings, such as Ctrl+E, Ctrl+D, etc.
        """
        def encrypt(*args, **kwargs):
            """
            The function to be called when Enter key is pressed on keyboard
            """
            if self.mainNotebook.index(self.mainNotebook.select()) == 0:
                # If the encryption tab is selected, call the encryption method
                self.crypto.encrypt()
            elif self.mainNotebook.index(self.mainNotebook.select()) == 1:
                # If the decryption tab is selected, call the decryption method
                self.crypto.decrypt()
            else:
                # Otherwise, don't call anything
                return

        def show_source(*args, **kwargs):
            """
            The function to make the source code tab in mainNotebook visible
            """
            self.mainNotebook.add(self.mainNotebook.sourceFrame, text="Source Code")
            if any(["source" in child for child in self.mainNotebook.tabs()]):
                self.mainNotebook.select(5)

        self.bind("<Return>", encrypt)

        self.bind("<Control_L><Alt_L>t", lambda _: self.theme.set_theme("vista"))
        self.bind("<Control_L>e", lambda _: self.mainNotebook.select(0))
        self.bind("<Control_L>d", lambda _: self.mainNotebook.select(1))
        self.bind("<Control_L>m", lambda _: self.mainNotebook.select(2))
        self.bind("<Control_L>l", lambda _: self.mainNotebook.select(3))
        self.bind("<F1>", lambda _: self.mainNotebook.select(4))
        # EASTER EGG! This keybind shows the source code of the program
        self.bind("<Control_L><Alt_L>s", show_source)

    
    def clipboard_get(self) -> Optional[str]:
        """
        Override the clipboard_get method to use pyperclip rather than the built-in copy/paste functions in Tkinter
        """
        clipboard: Optional[str] = pyperclip.paste()
        if not clipboard:
            return str()
        elif len(clipboard) > 15000:
            if messagebox.askyesno("Super long text", "The text you're trying to paste is too long (longer than 15.000 characters) which can cause the program to freeze. Are you sure?"):
                return clipboard
            else:
                return str()
        else:
            return clipboard

    
    def clipboard_set(self, text: str = None):
        """
        Override the clipboard_get method as well to use pyperclip
        """
        pyperclip.copy(text)

    # class Settings(Toplevel):
    #     def __init__(self, master: Tk):
    #         self.master = master
            
    #         self.grab_set()
    #         self.width = 200
    #         self.height = 200

    #         self.wm_title("Encrypt-n-Decrypt Settings")
    #         self.wm_geometry(f"{self.width}x{self.height}")
    #         self.wm_resizable(height=False, width=False)
    #         self.wm_attributes("-fullscreen", False)
    #         self.wm_maxsize(self.width, self.height)
    #         self.wm_minsize(self.width, self.height)


    

if __name__ == "__main__":
    # root = Tk()
    root = Interface()
    root.mainloop()
    
    
    

