import tkinter as tk


class PGPApp:
    def __init__(self, root):
        self.back_button = None
        self.root = root
        self.root.title("PGP Scheme")
        self.root.geometry("700x600")
        self.root.configure(bg="#2c3e50")  # Set the background color

        # Define button click functions
        self.button_functions = [
            self.generate_keys_button_click,
            self.delete_keys_button_click,
            self.import_keys_button_click,
            self.export_keys_button_click,
            self.send_message_button_click,
            self.receive_message_button_click,
            self.show_rings_button_click
        ]

        self.create_buttons()
        self.create_back_button()
        self.center_buttons_vertically()

    def show_generate_key_form(self):
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        name_label = tk.Label(form_frame, text="Name:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        name_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        email_label = tk.Label(form_frame, text="Email:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        email_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        key_size_label = tk.Label(form_frame, text="Key Size:", bg="#2c3e50", fg="white", font=("Helvetica", 14))

        key_size_var = tk.IntVar(value=1024)
        key_size_1024 = tk.Radiobutton(form_frame, text="1024", variable=key_size_var, value=1024, bg="#2c3e50",
                                       fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0, highlightthickness=0)
        key_size_2048 = tk.Radiobutton(form_frame, text="2048", variable=key_size_var, value=2048, bg="#2c3e50",
                                       fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0, highlightthickness=0)

        generate_button = tk.Button(form_frame, text="Generate",
                                    command=lambda: self.show_generate_key_password_form(name_entry.get(), email_entry.get(),
                                                                      key_size_var.get()), bg="#3498db", fg="white",
                                    font=("Helvetica", 14))

        name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        email_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        email_entry.grid(row=1, column=1, padx=5, pady=5)
        key_size_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        key_size_1024.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        key_size_2048.grid(row=2, column=1, padx=5, pady=5, sticky="e")
        generate_button.grid(row=1, column=3, padx = 30, pady=10)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def show_generate_key_password_form(self, name, email, size):
        self.clear_window()
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        password_label = tk.Label(form_frame, text="Password:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        password_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        generate_button = tk.Button(form_frame, text="Generate",
                                    command=lambda: self.generate_key(name,email,size, password_entry.get()),
                                    bg="#3498db", fg="white",
                                    font=("Helvetica", 14))

        password_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        password_entry.grid(row=0, column=1, padx=5, pady=5)
        generate_button.grid(row=0, column=3, padx=30, pady=10)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)


    def show_delete__key_form(self):
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        name_label = tk.Label(form_frame, text="Name:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        name_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        email_label = tk.Label(form_frame, text="Email:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        email_entry = tk.Entry(form_frame, font=("Helvetica", 14))


        password_label = tk.Label(form_frame, text="Password:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        password_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        generate_button = tk.Button(form_frame, text="Delete",
                                    command=lambda: self.delete_key(name_entry.get(), email_entry.get(), password_entry.get()), bg="#3498db", fg="white",
                                    font=("Helvetica", 14))

        name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        email_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        email_entry.grid(row=1, column=1, padx=5, pady=5)
        password_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        password_entry.grid(row=2, column=1, padx=5, pady=5)
        generate_button.grid(row=1, column=3, padx = 30, pady=10)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)


    def generate_key(self, name, email, size, password):
        self.clear_window()
        #TODO Implement calling actual generate key function
        textt = "Generating key for\n" + name + " " + email + " " + str(size) + " " + password
        label = tk.Label(self.root, text=textt, bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()


    def delete_key(self, name, email, password):
        self.clear_window()
        #TODO Implement calling actual delete key function
        textt = "Deleting key for\n" + name + " " + email + " "  + " " + password
        label = tk.Label(self.root, text=textt, bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def generate_keys_button_click(self):
        self.clear_window()
        self.show_generate_key_form()

    def delete_keys_button_click(self):
        self.clear_window()
        self.show_delete__key_form()

    def import_keys_button_click(self):
        self.clear_window()
        label = tk.Label(self.root, text="Import Keys (.pem) clicked", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def export_keys_button_click(self):
        self.clear_window()
        label = tk.Label(self.root, text="Export Keys (.pem) clicked", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def send_message_button_click(self):
        self.clear_window()
        label = tk.Label(self.root, text="Send Message clicked", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def receive_message_button_click(self):
        self.clear_window()
        label = tk.Label(self.root, text="Receive Message clicked", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def show_rings_button_click(self):
        self.clear_window()
        label = tk.Label(self.root, text="Show Rings Of Keys clicked", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def back_to_menu(self):
        self.clear_window()
        self.create_buttons()
        self.create_back_button()
        self.center_buttons_vertically()

    def create_buttons(self):
        self.buttons = [
            tk.Button(self.root, text="Generate RSA Keys", command=self.generate_keys_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold")),
            tk.Button(self.root, text="Delete RSA Keys", command=self.delete_keys_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold")),
            tk.Button(self.root, text="Import Keys (.pem)", command=self.import_keys_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold")),
            tk.Button(self.root, text="Export Keys (.pem)", command=self.export_keys_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold")),
            tk.Button(self.root, text="Send Message", command=self.send_message_button_click, bg="#3498db", fg="white",
                      font=("Helvetica", 12, "bold")),
            tk.Button(self.root, text="Receive Message", command=self.receive_message_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold")),
            tk.Button(self.root, text="Show Rings Of Keys", command=self.show_rings_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold"))
        ]

    def create_back_button(self):
        self.back_button = tk.Button(self.root, text="◀", command=self.back_to_menu, bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        self.back_button.place(x=10, y=10)

    def center_buttons_vertically(self):
        button_width = 300
        button_height = 60
        padding = 15
        total_height = len(self.buttons) * (button_height + padding) - padding
        x_start = (700 - button_width) // 2
        y_start = (600 - total_height) // 2

        for i, button in enumerate(self.buttons):
            y = y_start + i * (button_height + padding)
            button.place(x=x_start, y=y, width=button_width, height=button_height)

    def clear_window(self):
        for widget in self.root.winfo_children():
            if widget != self.back_button:
                widget.destroy()


# Create the main window
root = tk.Tk()

# Instantiate the PGPApp class
app = PGPApp(root)

# Start the Tkinter event loop
root.mainloop()
