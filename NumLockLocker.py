import sys
import os
import ctypes
import threading
import configparser
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QPushButton,
    QVBoxLayout,
    QMessageBox,
    QLabel
)
from PyQt5.QtCore import Qt
import pyautogui
import keyboard
import winreg

class NumLockController(QWidget):
    def __init__(self):
        super().__init__()
        self.locked = True  # Initialize with a default value
        self.num_lock_handler = None  # To store the keyboard handler
        self.is_admin = self.check_admin()  # Check admin status
        self.load_settings()
        self.initUI()
        if not self.is_admin:
            self.prompt_admin()
        self.set_num_lock_state(initial=True)  # Ensure initial state
        self.manage_keyboard_handler()
        self.start_monitoring()

    def check_admin(self):
        """
        Check if the script is running with administrative privileges.
        
        Returns:
            bool: True if running as admin, False otherwise.
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def prompt_admin(self):
        """
        Prompt the user to restart the application with administrative privileges.
        """
        reply = QMessageBox.question(
            self,
            'Administrative Privileges Required',
            "This application needs to run with administrative privileges to function correctly.\n"
            "Do you want to restart it with elevated permissions?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        if reply == QMessageBox.Yes:
            # Relaunch the script with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, '"' + os.path.abspath(sys.argv[0]) + '"', None, 1)
            sys.exit()
        else:
            QMessageBox.warning(
                self,
                'Insufficient Privileges',
                "The application may not function correctly without administrative privileges.",
                QMessageBox.Ok
            )

    def initUI(self):
        """
        Initialize the GUI components.
        """
        self.setWindowTitle('Num Lock Controller')
        self.setFixedSize(400, 300)  # Adjusted size for additional elements
        layout = QVBoxLayout()

        # Button to toggle Num Lock lock state
        self.button = QPushButton('Initializing...', self)
        self.button.setFixedSize(200, 50)
        self.button.clicked.connect(self.toggle_num_lock)
        layout.addWidget(self.button, alignment=Qt.AlignCenter)

        # Label to show Num Lock status
        self.status_label = QLabel('Status: Initializing...', self)
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet('font-size: 14px;')
        layout.addWidget(self.status_label, alignment=Qt.AlignCenter)

        # Label to show admin status
        self.admin_label = QLabel('Admin Status: Checking...', self)
        self.admin_label.setAlignment(Qt.AlignCenter)
        self.admin_label.setStyleSheet('font-size: 12px; color: gray;')
        layout.addWidget(self.admin_label, alignment=Qt.AlignCenter)

        # Button to capture Num Lock key
        self.capture_button = QPushButton('Capture Num Lock Key', self)
        self.capture_button.setFixedSize(200, 40)
        self.capture_button.clicked.connect(self.capture_num_lock_key)
        layout.addWidget(self.capture_button, alignment=Qt.AlignCenter)

        # Label to show captured Num Lock key
        self.captured_key_label = QLabel('Captured Key: Not Set', self)
        self.captured_key_label.setAlignment(Qt.AlignCenter)
        self.captured_key_label.setStyleSheet('font-size: 12px; color: blue;')
        layout.addWidget(self.captured_key_label, alignment=Qt.AlignCenter)

        self.setLayout(layout)
        self.update_ui()

    def load_settings(self):
        """
        Load user settings from the configuration file.
        """
        self.config = configparser.ConfigParser()
        self.config_file = 'settings.ini'
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
            self.locked = self.config.getboolean('Settings', 'locked', fallback=True)
            self.num_lock_key = self.config.get('Settings', 'num_lock_key', fallback='num lock')
        else:
            self.locked = True  # Default state
            self.num_lock_key = 'num lock'  # Default key name

    def save_settings(self):
        """
        Save user settings to the configuration file.
        """
        if not self.config.has_section('Settings'):
            self.config.add_section('Settings')
        self.config.set('Settings', 'locked', str(self.locked))
        self.config.set('Settings', 'num_lock_key', self.num_lock_key)
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)

    def update_ui(self):
        """
        Update the button's text and color based on the Num Lock state.
        """
        if self.locked:
            self.button.setText('Num Lock Locked')
            self.button.setStyleSheet('background-color: green; color: white;')
            self.status_label.setText('Status: Num Lock is On')
        else:
            self.button.setText('Num Lock Unlocked')
            self.button.setStyleSheet('background-color: lightcoral; color: white;')
            self.status_label.setText('Status: Num Lock is Off')

        # Update admin status label
        if self.is_admin:
            self.admin_label.setText('Admin Status: Running as Administrator')
            self.admin_label.setStyleSheet('font-size: 12px; color: green;')
        else:
            self.admin_label.setText('Admin Status: Not Running as Administrator')
            self.admin_label.setStyleSheet('font-size: 12px; color: red;')

        # Update key info label
        self.captured_key_label.setText(f'Captured Key: {self.num_lock_key}')

    def toggle_num_lock(self):
        """
        Toggle the Num Lock lock state based on user interaction.
        """
        self.locked = not self.locked
        self.save_settings()
        self.set_num_lock_state()
        self.update_ui()
        self.manage_keyboard_handler()

    def set_num_lock_state(self, initial=False):
        """
        Set the Num Lock key to the desired state.

        Parameters:
            initial (bool): Indicates if this is the initial setting during startup.
        """
        current_state = self.get_num_lock_state()
        if self.locked and not current_state:
            pyautogui.press('numlock')
        elif not self.locked and current_state:
            pyautogui.press('numlock')
        if initial:
            # Update UI after initial setting
            self.update_ui()

    def get_num_lock_state(self):
        """
        Retrieve the current state of the Num Lock key.

        Returns:
            bool: True if Num Lock is on, False otherwise.
        """
        hllDll = ctypes.WinDLL("User32.dll")
        return (hllDll.GetKeyState(0x90) & 1) == 1

    def capture_num_lock_key(self):
        """
        Capture the next key press or key combination to set as the Num Lock key.
        """
        QMessageBox.information(
            self,
            'Capture Key',
            'Please press the key or key combination you wish to assign as the Num Lock key.\n'
            'Note: Capturing key combinations involving the Fn key may not work as expected.',
            QMessageBox.Ok
        )
        
        # Reset captured keys
        self.captured_keys = []
        
        # Define a temporary callback to capture the next key press
        def on_press(event):
            try:
                if event.name:
                    self.captured_keys.append(event.name)
                else:
                    self.captured_keys.append(event.scan_code)
            except AttributeError:
                pass

            # Stop the listener after capturing the key
            return False  # Returning False stops the listener

        # Start a keyboard listener for one key press
        keyboard.on_press(on_press)
        keyboard.wait()  # Wait until a key is pressed

        # Process the captured key(s)
        self.process_captured_keys()

    def process_captured_keys(self):
        """
        Process and save the captured key(s) as the Num Lock trigger.
        """
        if not self.captured_keys:
            QMessageBox.warning(
                self,
                'Capture Failed',
                'No key was captured. Please try again.',
                QMessageBox.Ok
            )
            return

        # Join multiple keys with '+' to represent key combinations
        captured_key = '+'.join(self.captured_keys)

        # Update the label to show the captured key
        self.captured_key_label.setText(f'Captured Key: {captured_key}')

        # Save the captured key to settings
        self.num_lock_key = captured_key
        self.save_settings()

        # Update the keyboard handler with the new key
        self.manage_keyboard_handler()

        QMessageBox.information(
            self,
            'Capture Successful',
            f'Captured Num Lock Key: {captured_key}',
            QMessageBox.Ok
        )

    def manage_keyboard_handler(self):
        """
        Register or unregister the Num Lock key handler based on the lock state and captured key.
        """
        if self.locked:
            if self.num_lock_handler is not None:
                # Unhook previous handler if any
                keyboard.remove_hotkey(self.num_lock_handler)
                self.num_lock_handler = None

            # Register the new handler with suppression
            try:
                self.num_lock_handler = keyboard.add_hotkey(self.num_lock_key, self.on_num_lock_toggle, suppress=True)
                print(f"Registered hotkey: {self.num_lock_key}")
            except Exception as e:
                QMessageBox.critical(
                    self,
                    'Error',
                    f"Failed to register the hotkey '{self.num_lock_key}'.\nError: {e}",
                    QMessageBox.Ok
                )
                print(f"Error registering hotkey: {e}")
        else:
            if self.num_lock_handler is not None:
                # Unregister the handler
                keyboard.remove_hotkey(self.num_lock_handler)
                self.num_lock_handler = None
                print(f"Unregistered hotkey: {self.num_lock_key}")

    def on_num_lock_toggle(self):
        """
        Callback function triggered when the captured Num Lock key is pressed.
        """
        if self.locked:
            # Ensure Num Lock is on
            if not self.get_num_lock_state():
                pyautogui.press('numlock')

    def start_monitoring(self):
        """
        Start a background thread to monitor the Num Lock state continuously.
        """
        self.monitor_thread = threading.Thread(target=self.monitor_num_lock, daemon=True)
        self.monitor_thread.start()

    def monitor_num_lock(self):
        """
        Continuously monitor the Num Lock state and enforce the desired state.
        """
        while True:
            current_state = self.get_num_lock_state()
            if self.locked and not current_state:
                pyautogui.press('numlock')
            elif not self.locked and current_state:
                pyautogui.press('numlock')
            
            # Update the GUI
            self.status_label.setText('Status: Num Lock is On' if self.locked else 'Status: Num Lock is Off')
            self.button.setText('Num Lock Locked' if self.locked else 'Num Lock Unlocked')
            
            # Update button color
            if self.locked:
                self.button.setStyleSheet('background-color: green; color: white;')
            else:
                self.button.setStyleSheet('background-color: lightcoral; color: white;')
            
            # Sleep for a short interval to prevent high CPU usage
            threading.Event().wait(0.5)

    def closeEvent(self, event):
        """
        Override the close event to confirm exit with the user.
        """
        reply = QMessageBox.question(
            self,
            'Exit',
            "Are you sure you want to exit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Unhook the keyboard handler if active
            if self.num_lock_handler is not None:
                keyboard.remove_hotkey(self.num_lock_handler)
            event.accept()
        else:
            event.ignore()

def add_to_startup():
    """
    Add the script to Windows startup by creating a registry entry.
    """
    try:
        # Get the absolute path to the script
        script_path = os.path.abspath(sys.argv[0])
        # Create the command to execute
        command = f'"{sys.executable}" "{script_path}"'
        # Open the registry key for current user
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        # Set the value; "NumLockController" is the name of the entry
        winreg.SetValueEx(key, "NumLockController", 0, winreg.REG_SZ, command)
        winreg.CloseKey(key)
        print("Successfully added to startup.")
    except Exception as e:
        print(f"Failed to add to startup: {e}")

def remove_from_startup():
    """
    Remove the script from Windows startup by deleting the registry entry.
    """
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_ALL_ACCESS
        )
        winreg.DeleteValue(key, "NumLockController")
        winreg.CloseKey(key)
        print("Successfully removed from startup.")
    except FileNotFoundError:
        print("Startup entry not found.")
    except Exception as e:
        print(f"Failed to remove from startup: {e}")

def main():
    """
    Main function to run the application.
    """
    # Add to startup
    add_to_startup()

    # Create the application and controller
    app = QApplication(sys.argv)
    controller = NumLockController()
    controller.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
