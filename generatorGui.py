import tkinter as tk
from tkinter import messagebox
import pyperclip
from generator import PasswordGenerator


def generate_password():
    """Generate a password and display it in a message box"""
    website = website_entry.get()
    password_length = length_entry.get()
    include_symbols = symbols_var.get()

    if not website or not password_length:
        messagebox.showerror("Error", "Please enter website and password length.")
        return

    try:
        password_length = int(password_length)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid password length.")
        return

    password = ""

    if include_symbols:
        password = PasswordGenerator.generate_password_with_symbols(password_length)
    else:
        password = PasswordGenerator.generate_password(password_length)

    messagebox.showinfo("Generated Password", f"Generated password for {website}:\n{password}")

    save_password(website, password)


def save_password(website, password):
    """Save the password to the text box"""
    password_text.insert(tk.END, f"Website: {website}\nPassword: {password}\n\n")


def copy_password():
    """Copy the selected password to the clipboard"""
    selected_text = password_text.get(tk.SEL_FIRST, tk.SEL_LAST)
    if selected_text:
        password = selected_text.split("Password: ")[1]
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard.")
    else:
        messagebox.showerror("Error", "No password selected.")


def retrieve_password():
    """Retrieve the password for the given key"""
    key = key_entry.get()
    password = find_password(key)

    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Retrieved", "Password retrieved and copied to clipboard.")
    else:
        messagebox.showerror("Error", "Password not found.")


def find_password(key):
    """Find the password for the given key"""
    text_content = password_text.get("1.0", tk.END)
    password_lines = text_content.split("\n\n")

    for line in password_lines:
        if line.startswith("Website:"):
            line_key = line.split("Website: ")[1]
            if line_key == key:
                password = line.split("Password: ")[1]
                return password

    return None


# Create the main window
window = tk.Tk()
window.title("Password Generator")

# Password Generator Section
generator_frame = tk.Frame(window)
generator_frame.pack(side=tk.LEFT)

website_label = tk.Label(generator_frame, text="Website:")
website_label.pack()
website_entry = tk.Entry(generator_frame)
website_entry.pack()

length_label = tk.Label(generator_frame, text="Password Length:")
length_label.pack()
length_entry = tk.Entry(generator_frame)
length_entry.pack()

symbols_var = tk.BooleanVar()
symbols_check = tk.Checkbutton(generator_frame, text="Include Symbols", variable=symbols_var)
symbols_check.pack()

generate_button = tk.Button(generator_frame, text="Generate", command=generate_password)
generate_button.pack()

# Password Storage Section
storage_frame = tk.Frame(window)
storage_frame.pack(side=tk.RIGHT)

password_text = tk.Text(storage_frame, height=10, width=30)
password_text.pack(side=tk.LEFT)

copy_button = tk.Button(storage_frame, text="Copy Password", command=copy_password)
copy_button.pack()

key_label = tk.Label(storage_frame, text="Enter Key:")
key_label.pack()
key_entry = tk.Entry(storage_frame)
key_entry.pack()

retrieve_button = tk.Button(storage_frame, text="Retrieve Password", command=retrieve_password)
retrieve_button.pack()

# Start the GUI event loop
window.mainloop()
