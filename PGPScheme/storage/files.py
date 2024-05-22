class PGPFile:

    def __init__(self, file_path):
        self.file_path = file_path
        self.file = None

    def write_file_line(self, data):
        self.open_file('a')
        if self.file is None:
            return
        self.file.write(data+"\n")
        self.close_file()

    def write_file_list(self, data):
        self.open_file('a')
        if self.file is None:
            return
        for line in data:
            self.file.write(line+"\n")
        self.close_file()

    def read_file(self):
        self.open_file('r')
        if self.file is None:
            return
        lines = []
        for line in self.file:
            lines.append(line)
        self.close_file()
        return lines

    def clear_file(self):
        self.open_file('w')
        self.close_file()
        return

    def open_file(self, mode):
        try:
            self.file = open(self.file_path, mode)
        except FileNotFoundError:
            print("File not found, please check Path!")
            self.file = None

    def close_file(self):
        if self.file is not None:
            self.file.close()
        return
    