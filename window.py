from tkinter import *

# from main import *
# import last_try

import threading
import subprocess
import sys
import os

   

def btn_clicked2(c):
    window.iconify()
    subprocess.Popen("python ./last_try.py", shell=True)
    



def btn_clicked(d):
    window.iconify()
    subprocess.Popen("python ./main.py", shell=True)
    




window = Tk()
t1=""
t2=""
window.geometry("799x550")
window.configure(bg = "#ededed")
canvas = Canvas(
    window,
    bg = "#ededed",
    height = 550,
    width = 799,
    bd = 0,
    highlightthickness = 0,
    relief = "ridge")
canvas.place(x = 0, y = 0)

background_img = PhotoImage(file = f"background.png")
background = canvas.create_image(
    399.0, 275.0,
    image=background_img)

img0 = PhotoImage(file = f"img0.png")
b0 = Button(
    image = img0,
    borderwidth = 0,
    highlightthickness = 0,
    command = lambda: btn_clicked(t1),
    relief = "flat")

b0.place(
    x = 281, y = 434,
    width = 161,
    height = 46)

img1 = PhotoImage(file = f"img1.png")
b1 = Button(
    image = img1,
    borderwidth = 0,
    highlightthickness = 0,
    command = lambda: btn_clicked2(t2),
    relief = "flat")

b1.place(
    x = 561, y = 434,
    width = 161,
    height = 46)

window.resizable(False, False)
window.title("DATARMOR v1.0.0")
window.iconbitmap("icon.ico")
window.mainloop()
