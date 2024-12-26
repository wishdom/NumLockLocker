import sys
import os
import ctypes
import threading
import configparser
import logging
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
import winreg

# Configure logging
logging.basicConfig(
    filename='numlock_controller.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NumLockController(QWidget):
    def __init__(self):
        super().__init__()
        self.locked = True  # Initialize with a default value
        self.is_admin = self.check_admin()  # Check admin status
        self.load_settings()
        self.initUI()
        if not self.is_admin:
            self.prompt_admin()
        self.set_num_lock_state(initial=True)  # Ensure initial state
        self.start_monitoring()

    def check_admin(self):
        """
        Check if the script is running with administrative privileges.
        
        Returns:
            bool: True if running as admin, False otherwise.
        """
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            logging.debug(f"Admin check: {is_admin}")
            return is_admin
        except Exception as e:
            logging.error(f"Error checking admin status: {e}")
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
            try:
                # Relaunch the script with admin rights
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, '"' + os.path.abspath(sys.argv[0]) + '"', None, 1)
                logging.info("Relaunching script with administrative privileges.")
            except Exception as e:
                logging.error(f"Failed to relaunch as admin: {e}")
            sys.exit()
        else:
            QMessageBox.warning(
                self,
                'Insufficient Privileges',
                "The application may not function correctly without administrative privileges.",
                QMessageBox.Ok
            )
            logging.warning("Application not run as administrator.")
    
    def initUI(self):
        """
        Initialize the GUI components.
        """
        self.setWindowTitle('Num Lock Controller')
        self.setFixedSize(350, 200)  # Adjusted size for additional elements
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

        self.setLayout(layout)
        self.update_ui()

    def load_settings(self):
        """
        Load user settings from the configuration file.
        """
        self.config = configparser.ConfigParser()
        self.config_file = 'settings.ini'
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file)
                self.locked = self.config.getboolean('Settings', 'locked', fallback=True)
                logging.debug(f"Loaded settings: locked={self.locked}")
            except Exception as e:
                logging.error(f"Error reading settings.ini: {e}")
                self.locked = True  # Default to locked
        else:
            self.locked = True  # Default state
            logging.debug("settings.ini not found. Defaulting to locked=True")

    def save_settings(self):
        """
        Save user settings to the configuration file.
        """
        try:
            if not self.config.has_section('Settings'):
                self.config.add_section('Settings')
            self.config.set('Settings', 'locked', str(self.locked))
            with open(self.config_file, 'w') as configfile:
                self.config.write(configfile)
            logging.debug(f"Saved settings: locked={self.locked}")
        except Exception as e:
            logging.error(f"Error writing to settings.ini: {e}")

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

    def toggle_num_lock(self):
        """
        Toggle the Num Lock lock state based on user interaction.
        """
        self.locked = not self.locked
        self.save_settings()
        self.set_num_lock_state()
        self.update_ui()
        logging.info(f"User toggled lock: locked={self.locked}")

    def set_num_lock_state(self, initial=False):
        """
        Set the Num Lock key to the desired state.
        
        Parameters:
            initial (bool): Indicates if this is the initial setting during startup.
        """
        current_state = self.get_num_lock_state()
        logging.debug(f"Current Num Lock state: {current_state}")
        if self.locked and not current_state:
            pyautogui.press('numlock')
            logging.info("Num Lock set to On.")
        elif not self.locked and current_state:
            pyautogui.press('numlock')
            logging.info("Num Lock set to Off.")
        if initial:
            # Update UI after initial setting
            self.update_ui()

    def get_num_lock_state(self):
        """
        Retrieve the current state of the Num Lock key.
        
        Returns:
            bool: True if Num Lock is on, False otherwise.
        """
        try:
            hllDll = ctypes.WinDLL("User32.dll")
            state = (hllDll.GetKeyState(0x90) & 1) == 1
            logging.debug(f"GetKeyState for Num Lock: {state}")
            return state
        except Exception as e:
            logging.error(f"Error getting Num Lock state: {e}")
            return False  # Assume Off in case of error

    def start_monitoring(self):
        """
        Start a background thread to monitor the Num Lock state.
        """
        self.monitor_thread = threading.Thread(target=self.monitor_num_lock, daemon=True)
        self.monitor_thread.start()
        logging.info("Started Num Lock monitoring thread.")

    def monitor_num_lock(self):
        """
        Continuously monitor the Num Lock state and enforce the desired state.
        """
        while True:
            current_state = self.get_num_lock_state()
            if self.locked and not current_state:
                pyautogui.press('numlock')
                logging.info("Num Lock was turned Off. Re-enabling it.")
            elif not self.locked and current_state:
                pyautogui.press('numlock')
                logging.info("Num Lock was turned On. Disabling it.")
            # Update the GUI in the main thread
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
        Override the close event to ensure Num Lock remains On and confirm exit with the user.
        """
        reply = QMessageBox.question(
            self,
            'Exit',
            "Are you sure you want to exit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Ensure Num Lock is On before exiting
            if self.locked:
                try:
                    if not self.get_num_lock_state():
                        pyautogui.press('numlock')
                        logging.info("Num Lock was Off on exit. Re-enabling it.")
                except Exception as e:
                    logging.error(f"Error setting Num Lock on exit: {e}")
            event.accept()
            logging.info("Application closed by user.")
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
        logging.info("Successfully added to startup.")
    except Exception as e:
        logging.error(f"Failed to add to startup: {e}")

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
        logging.info("Successfully removed from startup.")
    except FileNotFoundError:
        logging.warning("Startup entry not found.")
    except Exception as e:
        logging.error(f"Failed to remove from startup: {e}")

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
