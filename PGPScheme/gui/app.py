import tkinter as tk


class PGPApp:
    def __init__(self, root):
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

    def generate_keys_button_click(self):
        self.clear_window()
        label = tk.Label(self.root, text="Generate RSA Keys clicked", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

    def delete_keys_button_click(self):
        self.clear_window()
        label = tk.Label(self.root, text="Delete RSA Keys clicked", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
        label.pack()

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
