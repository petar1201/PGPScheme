import tkinter as tk
from tkinter import simpledialog

from PGPScheme.security.configuration import *
from PGPScheme.message.message import *


class PGPApp:
    def __init__(self, root):
        self.back_button = None
        self.root = root

        self.root.title("PGP Scheme")
        self.root.geometry("950x600")
        self.root.configure(bg="#2c3e50")

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
                                       fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                                       highlightthickness=0)
        key_size_2048 = tk.Radiobutton(form_frame, text="2048", variable=key_size_var, value=2048, bg="#2c3e50",
                                       fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                                       highlightthickness=0)

        generate_button = tk.Button(form_frame, text="Generate",
                                    command=lambda: self.show_generate_key_password_form(name_entry.get(),
                                                                                         email_entry.get(),
                                                                                         key_size_var.get()),
                                    bg="#3498db", fg="white",
                                    font=("Helvetica", 14))

        name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        email_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        email_entry.grid(row=1, column=1, padx=5, pady=5)
        key_size_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        key_size_1024.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        key_size_2048.grid(row=2, column=1, padx=5, pady=5, sticky="e")
        generate_button.grid(row=1, column=3, padx=30, pady=10)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def show_generate_key_password_form(self, name, email, size):
        self.clear_window()
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        password_label = tk.Label(form_frame, text="Password:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        password_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        generate_button = tk.Button(form_frame, text="Generate",
                                    command=lambda: self.generate_key(name, email, size, password_entry.get()),
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

        generate_button = tk.Button(form_frame, text="Delete",
                                    command=lambda: self.delete_key(name_entry.get(), email_entry.get()), bg="#3498db",
                                    fg="white",
                                    font=("Helvetica", 14))

        name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        email_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        email_entry.grid(row=1, column=1, padx=5, pady=5)
        generate_button.grid(row=1, column=3, padx=30, pady=10)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def show_import_private_key_form(self):
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        private_path_label = tk.Label(form_frame, text="path:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        private_path_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        public_path_label = tk.Label(form_frame, text="path:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        public_path_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        status_label = tk.Label(self.root, text="", bg="#2c3e50", fg="white", font=("Helvetica", 14))

        private_button = tk.Button(form_frame, text="Import Private Keys",
                                   command=lambda: self.import_private_keys(private_path_entry.get(), status_label),
                                   bg="#3498db",
                                   fg="white",
                                   font=("Helvetica", 14))

        public_button = tk.Button(form_frame, text="Import Public Keys",
                                  command=lambda: self.import_public_keys(public_path_entry.get(), status_label),
                                  bg="#3498db",
                                  fg="white",
                                  font=("Helvetica", 14))

        private_path_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        private_path_entry.grid(row=0, column=1, padx=5, pady=5)
        public_path_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        public_path_entry.grid(row=1, column=1, padx=5, pady=5)
        private_button.grid(row=0, column=3, padx=30, pady=10)
        public_button.grid(row=1, column=3, padx=30, pady=10)

        status_label.pack(side=tk.BOTTOM)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def show_export_private_key_form(self):
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        private_path_label = tk.Label(form_frame, text="path:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        private_path_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        public_path_label = tk.Label(form_frame, text="path:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        public_path_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        status_label = tk.Label(self.root, text="", bg="#2c3e50", fg="white", font=("Helvetica", 14))

        private_button = tk.Button(form_frame, text="Export Private Keys",
                                   command=lambda: self.export_private_keys(private_path_entry.get(), status_label),
                                   bg="#3498db",
                                   fg="white",
                                   font=("Helvetica", 14))

        public_button = tk.Button(form_frame, text="Export Public Keys",
                                  command=lambda: self.export_public_keys(public_path_entry.get(), status_label),
                                  bg="#3498db",
                                  fg="white",
                                  font=("Helvetica", 14))

        private_path_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        private_path_entry.grid(row=0, column=1, padx=5, pady=5)
        public_path_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        public_path_entry.grid(row=1, column=1, padx=5, pady=5)
        private_button.grid(row=0, column=3, padx=30, pady=10)
        public_button.grid(row=1, column=3, padx=30, pady=10)

        status_label.pack(side=tk.BOTTOM)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def show_key_rings_form(self):
        buttons = [
            tk.Button(self.root, text="Show Private Key Ring", command=self.private_key_ring_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold")),
            tk.Button(self.root, text="Show Public Key Ring", command=self.public_key_ring_button_click, bg="#3498db",
                      fg="white", font=("Helvetica", 12, "bold"))]
        button_width = 300
        button_height = 60
        padding = 15
        total_height = len(buttons) * (button_height + padding) - padding
        x_start = (950 - button_width) // 2
        y_start = (600 - total_height) // 2

        for i, button in enumerate(buttons):
            y = y_start + i * (button_height + padding)
            button.place(x=x_start, y=y, width=button_width, height=button_height)

    def show_private_key_ring(self):

        private_key_data = private_key_ring_collection.get_ring_data()

        self.clear_window()

        canvas = tk.Canvas(self.root, bg="#2c3e50")
        scrollbar = tk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#2c3e50")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        headers = ["User ID", "Timestamp", "Key ID", "Public Key", "Encrypted Private Key"]
        for col, header in enumerate(headers):
            label = tk.Label(scrollable_frame, text=header, bg="#2c3e50", fg="white", font=("Helvetica", 12, "bold"),
                             padx=10, pady=5)
            label.grid(row=0, column=col, sticky="nsew")

        flag = 1
        for row, key in enumerate(private_key_data, start=1):
            pady = 5
            if flag == 1:
                pady = 20
                flag = 0
            tk.Label(scrollable_frame, text=key["user_id"], bg="#2c3e50", fg="white", font=("Helvetica", 12), padx=10,
                     pady=pady).grid(row=row, column=0, sticky="nsew")
            tk.Label(scrollable_frame, text=key["timestamp"], bg="#2c3e50", fg="white", font=("Helvetica", 12), padx=10,
                     pady=5).grid(row=row, column=1, sticky="nsew")
            tk.Label(scrollable_frame, text=key["key_id"], bg="#2c3e50", fg="white", font=("Helvetica", 12), padx=10,
                     pady=5).grid(row=row, column=2, sticky="nsew")
            public_key_button = tk.Button(scrollable_frame, text="Show",
                                          command=lambda pk=key["public_key"]: self.show_popup("Public Key", pk),
                                          bg="#3498db", fg="white", font=("Helvetica", 12))
            public_key_button.grid(row=row, column=3, padx=10, pady=5)
            encrypted_private_key_button = tk.Button(scrollable_frame, text="Show",
                                                     command=lambda epk=key["encrypted_private_key"]: self.show_popup(
                                                         "Encrypted Private Key", epk), bg="#3498db", fg="white",
                                                     font=("Helvetica", 12))
            encrypted_private_key_button.grid(row=row, column=4, padx=10, pady=5)

        self.create_back_button()
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def show_public_key_ring(self):
        public_data = public_key_ring_collection.get_ring_data()

        self.clear_window()

        canvas = tk.Canvas(self.root, bg="#2c3e50")
        scrollbar = tk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#2c3e50")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        headers = ["User ID", "Timestamp", "Key ID", "Public Key"]
        for col, header in enumerate(headers):
            label = tk.Label(scrollable_frame, text=header, bg="#2c3e50", fg="white", font=("Helvetica", 12, "bold"),
                             padx=10, pady=5)
            label.grid(row=0, column=col, sticky="nsew")

        flag = 1
        for row, key in enumerate(public_data, start=1):
            pady = 5
            if flag == 1:
                pady = 20
                flag = 0
            tk.Label(scrollable_frame, text=key["user_id"], bg="#2c3e50", fg="white", font=("Helvetica", 12), padx=70,
                     pady=pady).grid(row=row, column=0, sticky="nsew")
            tk.Label(scrollable_frame, text=key["timestamp"], bg="#2c3e50", fg="white", font=("Helvetica", 12), padx=10,
                     pady=5).grid(row=row, column=1, sticky="nsew")
            tk.Label(scrollable_frame, text=key["key_id"], bg="#2c3e50", fg="white", font=("Helvetica", 12), padx=10,
                     pady=5).grid(row=row, column=2, sticky="nsew")
            public_key_button = tk.Button(scrollable_frame, text="Show",
                                          command=lambda pk=key["public_key"]: self.show_popup("Public Key", pk),
                                          bg="#3498db", fg="white", font=("Helvetica", 12))
            public_key_button.grid(row=row, column=3, padx=10, pady=5)

        self.create_back_button()
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def show_send_message_form(self):
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        file_name_label = tk.Label(form_frame, text="Filename:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        file_name_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        data_label = tk.Label(form_frame, text="Message:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        data_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        alg_3des_var = tk.BooleanVar(value=False)
        alg_3des = tk.Checkbutton(form_frame, text="3DES", variable=alg_3des_var, bg="#2c3e50",
                                  fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                                  highlightthickness=0)

        alg_aes_var = tk.BooleanVar(value=False)
        alg_aes = tk.Checkbutton(form_frame, text="AES", variable=alg_aes_var, bg="#2c3e50",
                                 fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                                 highlightthickness=0)

        security_var = tk.BooleanVar(value=False)
        security = tk.Checkbutton(form_frame, text="Security", variable=security_var, bg="#2c3e50",
                                  fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                                  highlightthickness=0)

        authentication_var = tk.BooleanVar(value=False)
        authentication = tk.Checkbutton(form_frame, text="Authentication", variable=authentication_var, bg="#2c3e50",
                                        fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                                        highlightthickness=0)

        zip_var = tk.BooleanVar(value=False)
        zip = tk.Checkbutton(form_frame, text="Compress", variable=zip_var, bg="#2c3e50",
                             fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                             highlightthickness=0)

        radix_var = tk.BooleanVar(value=False)
        radix = tk.Checkbutton(form_frame, text="Radix", variable=radix_var, bg="#2c3e50",
                               fg="white", font=("Helvetica", 14), selectcolor="#2c3e50", borderwidth=0,
                               highlightthickness=0)

        status_label = tk.Label(self.root, text="", bg="#2c3e50", fg="white", font=("Helvetica", 14))

        send_button = tk.Button(form_frame, text="Send",
                                command=lambda: self.send_message(file_name_entry.get(), data_entry.get(),
                                                                  alg_3des_var.get(), alg_aes_var.get(),
                                                                  security_var.get(), authentication_var.get(),
                                                                  zip_var.get(), radix_var.get(), status_label),
                                bg="#3498db", fg="white",
                                font=("Helvetica", 14))

        file_name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        file_name_entry.grid(row=0, column=1, padx=5, pady=5)
        data_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        data_entry.grid(row=1, column=1, padx=5, pady=5)
        alg_3des.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        alg_aes.grid(row=2, column=1, padx=5, pady=5, sticky="e")
        authentication.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        security.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        zip.grid(row=5, column=1, padx=5, pady=5, sticky="w")
        radix.grid(row=6, column=1, padx=5, pady=5, sticky="w")
        send_button.grid(row=7, column=0, columnspan=2, padx=5, pady=10)

        status_label.pack(side=tk.BOTTOM)

        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def get_value(self, prompt):
        self.root.deiconify()
        value = simpledialog.askstring("Input", prompt, parent=self.root)
        self.root.withdraw()
        return value

    def send_message(self, filename, message, alg_3des, alg_aes, security, authentication, compress, radix,
                     status_label):
        alg = []
        if alg_3des:
            alg.append("3DES")
        if alg_aes:
            alg.append("AES")
        alg_value = ','.join(alg)

        filepath = f"../resources/inbox/{filename}.pem"

        header = Header(
            1 if authentication else 0,
            1 if security else 0,
            1 if compress else 0,
            1 if radix else 0,
            alg_value.lower() if alg_value else "3des"
        )
        auth_data = None
        sec_data = None
        if authentication:
            user_id_sender = self.get_value("Enter sender user id")
            passphrase = self.get_value("Enter passphrase")
            auth_data = AuthenticationData(passphrase, user_id_sender)
        if security:
            user_id_receiver = self.get_value("Enter receiver user id")
            sec_data = SecurityData(user_id_receiver)
        mess = Message()
        self.root.deiconify()
        try:
            mess.send(message, filepath, header, auth_data, sec_data)
            status_label.config(text="Message Sent")
        except Exception as e:
            status_label.config(text="Failed to send message")
            print(e)

    def show_receive_message_form(self):
        form_frame = tk.Frame(self.root, bg="#2c3e50")

        file_name_label = tk.Label(form_frame, text="Filename:", bg="#2c3e50", fg="white", font=("Helvetica", 14))
        file_name_entry = tk.Entry(form_frame, font=("Helvetica", 14))

        status_label = tk.Label(self.root, text="", bg="#2c3e50", fg="white", font=("Helvetica", 14))

        send_button = tk.Button(form_frame, text="Receive",
                                command=lambda: self.receive_message(file_name_entry.get(), status_label),
                                bg="#3498db", fg="white",
                                font=("Helvetica", 14))

        status_label.pack(side=tk.BOTTOM)

        file_name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        file_name_entry.grid(row=0, column=1, padx=5, pady=5)
        send_button.grid(row=0, column=2, padx=5, pady=10)
        form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def receive_message(self, filename, status_label):
        filepath = f"../resources/inbox/{filename}.pem"
        mess = Message()
        try:
            flag, id = mess.receive(filepath)
            passphrase = None
            if flag:
                passphrase = self.get_value(
                    f"Enter passphrase for {private_key_ring_collection.get_key_pair_by_key_id(id).get_user_id()}")
                self.root.deiconify()
            self.show_popup("Received Message", mess.read(passphrase))
            status_label.config(text="Message received")
        except Exception as e:
            status_label.config(text="Failed to receive message")
            print(e)

    def show_popup(self, title, content):
        popup = tk.Toplevel()
        popup.title(title)
        popup.geometry("400x200")
        popup.configure(bg="#2c3e50")

        text_box = tk.Text(popup, wrap='word', bg="#2c3e50", fg="white", font=("Helvetica", 12))
        text_box.insert('1.0', content)
        text_box.config(state="disabled")
        text_box.pack(expand=True, fill='both', padx=10, pady=10)

    def private_key_ring_button_click(self):
        self.clear_window()
        self.show_private_key_ring()

    def public_key_ring_button_click(self):
        self.clear_window()
        self.show_public_key_ring()

    def import_private_keys(self, path, status_label):
        try:
            private_key_ring_collection.import_key_ring_from_pem(
                path if path else "../resources/keys/private_keys.pem"
            )
            status_label.config(text="Import Private Keys Successfully")
        except Exception:
            status_label.config(text="Import Private Keys Failed")

    def import_public_keys(self, path, status_label):
        try:
            public_key_ring_collection.import_key_ring_from_pem(
                path if path else "../resources/keys/public_key.pem"
            )
            status_label.config(text="Import Public Keys Successfully")
        except Exception:
            status_label.config(text="Import Public Keys Failed")

    def export_private_keys(self, path, status_label):
        try:
            private_key_ring_collection.export_key_ring_to_pem(
                path if path else "../resources/keys/private_keys.pem"
            )
            status_label.config(text="Export Private Keys Successfully")
        except Exception:
            status_label.config(text="Export Private Keys Failed")

    def export_public_keys(self, path, status_label):
        try:
            public_key_ring_collection.export_key_ring_to_pem(
                path if path else "../resources/keys/public_key.pem"
            )
            status_label.config(text="Export Public Keys Successfully")
        except Exception:
            status_label.config(text="Export Public Keys Failed")

    def generate_key(self, name, email, size, password):
        self.clear_window()
        try:
            private_key_ring_collection.add_key_pair(name, email, password, size)
            public_key_ring_collection.add_key_pair(f"{email}|{name}",
                                                    private_key_ring_collection.get_key_pair_by_user_id(
                                                        f"{email}|{name}").get_public_key())
            textt = "Generated key for\n" + name + " " + email + " " + str(size) + " " + password
        except Exception:
            textt = "Key Generation Failed for for\n" + name + " " + email + " " + str(size) + " " + password

        label = tk.Label(self.root, text=textt, bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def delete_key(self, name, email):
        self.clear_window()
        try:
            private_key_ring_collection.delete_key_pair(name, email)
            public_key_ring_collection.delete_key_pair_by_user_id(f"{email}|{name}")
            textt = "Deleted key for\n" + name + " " + email
        except KeyError:
            textt = "No key for \n" + name + " " + email

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
        self.show_import_private_key_form()

    def export_keys_button_click(self):
        self.clear_window()
        self.show_export_private_key_form()

    def send_message_button_click(self):
        self.clear_window()
        self.show_send_message_form()

    def receive_message_button_click(self):
        self.clear_window()
        self.show_receive_message_form()

    def show_rings_button_click(self):
        self.clear_window()
        self.show_key_rings_form()

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
        self.back_button = tk.Button(self.root, text="◀", command=self.back_to_menu, bg="#2c3e50", fg="white",
                                     font=("Helvetica", 16, "bold"))
        self.back_button.place(x=10, y=10)

    def center_buttons_vertically(self):
        button_width = 300
        button_height = 60
        padding = 15
        total_height = len(self.buttons) * (button_height + padding) - padding
        x_start = (950 - button_width) // 2
        y_start = (600 - total_height) // 2

        for i, button in enumerate(self.buttons):
            y = y_start + i * (button_height + padding)
            button.place(x=x_start, y=y, width=button_width, height=button_height)

    def clear_window(self):
        for widget in self.root.winfo_children():
            if widget != self.back_button:
                widget.destroy()


root = tk.Tk()
app = PGPApp(root)
root.mainloop()
