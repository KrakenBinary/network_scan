#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import random
import os
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.style import Style
from rich.align import Align
from rich.box import DOUBLE, HEAVY

# ANSI colors for consistent use throughout the application
# Retro hacker color scheme
MATRIX_GREEN = "\033[38;2;0;255;0m"      # Classic matrix green
PHOSPHOR_GREEN = "\033[38;2;57;255;20m"  # Old phosphor monitor green
AMBER_TERMINAL = "\033[38;2;255;191;0m"  # Old amber terminal
DIGITAL_CYAN = "\033[38;2;0;255;255m"    # Digital cyan
WARNING_RED = "\033[38;2;255;80;80m"     # Warning red
ALERT_YELLOW = "\033[38;2;255;255;0m"    # Alert yellow
IBM_BLUE = "\033[38;2;0;160;255m"        # Old IBM blue
VIOLET_PURPLE = "\033[38;2;138;43;226m"  # Violet for special outputs
RESET = "\033[0m"

# Background colors for special emphasis
BG_BLACK = "\033[40m"
BG_GREEN = "\033[42m"
BG_BLUE = "\033[44m"

# Text effects
BOLD = "\033[1m"
BLINK = "\033[5m"
INVERT = "\033[7m"
DIM = "\033[2m"

# Message types for the output manager
MSG_NORMAL = "normal"
MSG_SUCCESS = "success" 
MSG_INFO = "info"
MSG_WARNING = "warning"
MSG_ERROR = "error"

# ASCII art collection
ASCII_LOGO = """
    ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    ▄▄▄█████▓▓█████  ██▀███   ███▄ ▄███▓ ██▓ ███▄    █  █████▒▒█████  
    ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▓██   ▒▒██▒  ██▒
    ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒▓██    ▓██░▒██▒▓██  ▀█ ██▒▒████ ░▒██░  ██▒
    ░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  ▒██    ▒██ ░██░▓██▒  ▐▌██▒░▓█▒  ░▒██   ██░
      ▒██▒ ░ ░▒████▒░██▓ ▒██▒▒██▒   ░██▒░██░▒██░   ▓██░░▒█░   ░ ████▓▒░
      ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒  ▒ ░   ░ ▒░▒░▒░ 
        ░     ░ ░  ░  ░▒ ░ ▒░░  ░      ░ ▒ ░░ ░░   ░ ▒░ ░       ░ ▒ ▒░ 
      ░         ░     ░░   ░ ░      ░    ▒ ░   ░   ░ ░  ░ ░   ░ ░ ░ ▒  
                ░  ░   ░            ░    ░           ░          ░ ░  
"""

SKULL_LOGO = """
      ___           ___           ___     
     /\\  \\         /\\__\\         /\\  \\    
    /::\\  \\       /::|  |       /::\\  \\   
   /:/\\:\\  \\     /:|:|  |      /:/\\:\\  \\  
  /::\\~\\:\\  \\   /:/|:|__|__   /::\\~\\:\\  \\ 
 /:/\\:\\ \\:\\__\\ /:/ |::::\\__\\ /:/\\:\\ \\:\\__\\
 \\/__\\:\\/:/  / \\/__/~~/:/  / \\/__\\:\\/:/  /
      \\::/  /        /:/  /       \\::/  / 
      /:/  /        /:/  /        /:/  /  
     /:/  /        /:/  /        /:/  /   
     \\/__/         \\/__/         \\/__/    
"""

NETWORK_ART = """
    ┌───┐     ┌───┐     ┌───┐
    │ █ │━━━━━│ █ │━━━━━│ █ │
    └───┘     └───┘     └───┘
      ┃         ┃         ┃   
    ┌───┐     ┌───┐     ┌───┐
    │ █ │━━━━━│ █ │━━━━━│ █ │
    └───┘     └───┘     └───┘
      ┃         ┃         ┃   
    ┌───┐     ┌───┐     ┌───┐
    │ █ │━━━━━│ █ │━━━━━│ █ │
    └───┘     └───┘     └───┘
"""

class TerminalOutput:
    """Centralized terminal output manager for consistent UI styling"""
    
    def __init__(self):
        self.console = Console()
        # Get terminal size for adaptive rendering
        self.term_width, self.term_height = self._get_terminal_size()
        
    def _get_terminal_size(self):
        """Get terminal size, with fallbacks for various platforms"""
        try:
            columns, lines = os.get_terminal_size()
            return columns, lines
        except:
            # Fallback values if we can't detect
            return 80, 24
    
    def clear_screen(self):
        """Print a separator instead of clearing the screen"""
        print("\n" + "=" * 80 + "\n")
    
    def show_banner(self):
        """Display the ASCII art logo with retro styling"""
        self.clear_screen()
        banner = Panel(
            Align(Text(ASCII_LOGO, style="green"), align="center"),
            border_style="green",
            subtitle="v1.0.0 | Type 'help' for commands"
        )
        self.console.print(banner)
    
    def show_skull(self):
        """Display the skull ASCII art for cyber effects"""
        print(f"{MATRIX_GREEN}{SKULL_LOGO}{RESET}")
    
    def print(self, text, msg_type=MSG_NORMAL, newline=True, blink=False, bold=False):
        """Print text to the terminal with appropriate styling"""
        # Determine color based on message type
        # Support both constant values and string literals
        if msg_type == MSG_SUCCESS or msg_type == "success":
            color = PHOSPHOR_GREEN
        elif msg_type == MSG_INFO or msg_type == "info":
            color = IBM_BLUE
        elif msg_type == MSG_WARNING or msg_type == "warning":
            color = ALERT_YELLOW
        elif msg_type == MSG_ERROR or msg_type == "error":
            color = WARNING_RED
        else:
            color = MATRIX_GREEN
        
        # Add effects if requested
        effects = ""
        if bold:
            effects += BOLD
        if blink:
            effects += BLINK
        
        # Print with appropriate styling
        if newline:
            print(f"{effects}{color}{text}{RESET}")
        else:
            print(f"{effects}{color}{text}{RESET}", end="")
    
    def success(self, text):
        """Print a success message"""
        self.print(f"[+] {text}", MSG_SUCCESS)
    
    def info(self, text):
        """Print an info message"""
        self.print(f"[*] {text}", MSG_INFO)
    
    def warning(self, text):
        """Print a warning message"""
        self.print(f"[!] {text}", MSG_WARNING)
    
    def error(self, text):
        """Print an error message"""
        self.print(f"[✖] {text}", MSG_ERROR)
    
    def progress(self, percent, width=40):
        """Display a retro progress bar"""
        filled_width = int(width * percent / 100)
        bar = '█' * filled_width + '░' * (width - filled_width)
        print(f"\r{MATRIX_GREEN}[{bar}] {percent}%{RESET}", end='')
        sys.stdout.flush()
        if percent >= 100:
            print()
    
    def show_scanner_progress(self, text="SCANNING NETWORK...", progress=50):
        """Show a simplified scanner progress bar"""
        # Display text first
        self.info(text)
        # Then show the progress bar
        self.progress(progress)
        # Add a newline if we're not at 100%
        if progress < 100:
            print()
    
    def hacker_table(self, title, columns, rows, box="DOUBLE"):
        """Create a stylized retro hacker table"""
        # Handle different box styles properly
        box_style = DOUBLE
        if isinstance(box, str):
            if box == "DOUBLE":
                box_style = DOUBLE
            elif box == "HEAVY":
                box_style = HEAVY
            # Default to DOUBLE if not recognized
        else:
            box_style = box
            
        # Create table with proper parameters
        table = Table(
            title=str(title),  # Convert to string to avoid substitution issues
            border_style="green", 
            box=box_style
        )
        
        # Add columns with alternating styles
        for i, col in enumerate(columns):
            style = "green" if i % 2 == 0 else "cyan"
            table.add_column(str(col), style=style)  # Convert to string to avoid substitution issues
        
        # Add rows with cyberpunk styling - ensure all values are strings
        for row in rows:
            string_row = [str(item) for item in row]  # Convert all items to strings
            table.add_row(*string_row)
        
        self.console.print(table)
    
    def type_text(self, text, speed=0.02, msg_type=MSG_NORMAL, jitter=False, newline=True, bold=False):
        """Type text with a hacker-style animation"""
        # Determine color based on message type
        if msg_type == MSG_SUCCESS or msg_type == "success":
            color = PHOSPHOR_GREEN
            rich_color = "green"
        elif msg_type == MSG_INFO or msg_type == "info":
            color = IBM_BLUE
            rich_color = "blue"
        elif msg_type == MSG_WARNING or msg_type == "warning":
            color = ALERT_YELLOW
            rich_color = "yellow"
        elif msg_type == MSG_ERROR or msg_type == "error":
            color = WARNING_RED
            rich_color = "red"
        else:
            color = MATRIX_GREEN
            rich_color = "green"
            
        # Apply bold style if requested
        if bold:
            rich_color = f"bold {rich_color}"
            
        for char in text:
            if jitter and random.random() < 0.05:
                # Simulate typing errors and corrections
                typo = random.choice("qwertyuiopasdfghjklzxcvbnm")
                self.console.print(typo, style=rich_color, end="")
                sys.stdout.flush()
                time.sleep(speed * 2)
                self.console.print("\b", end="")
            
            # Randomize typing speed if jitter is enabled
            delay = speed
            if jitter:
                delay = speed * random.uniform(0.5, 1.5)
                
            # Print character with appropriate styling
            self.console.print(char, style=rich_color, end="")
            sys.stdout.flush()
            time.sleep(delay)
            
        if newline:
            print()  
    
    def glitch_text(self, text, iterations=3, speed=0.1, msg_type=MSG_NORMAL):
        """Create a glitching text effect"""
        # Determine color based on message type
        if msg_type == MSG_SUCCESS or msg_type == "success":
            color = PHOSPHOR_GREEN
        elif msg_type == MSG_INFO or msg_type == "info":
            color = IBM_BLUE
        elif msg_type == MSG_WARNING or msg_type == "warning":
            color = ALERT_YELLOW
        elif msg_type == MSG_ERROR or msg_type == "error":
            color = WARNING_RED
        else:
            color = MATRIX_GREEN
        
        glitch_chars = "!@#$%^&*()_+-=[]\\{}|;':\",./<>?`~"
        
        for i in range(iterations):
            # Generate glitched version of text
            glitched = ""
            for char in text:
                if random.random() < 0.3:  # 30% chance to replace with glitch char
                    glitched += random.choice(glitch_chars)
                else:
                    glitched += char
                    
            # Print the glitched text, then clear it
            print(f"\r{color}{glitched}{RESET}", end="")
            sys.stdout.flush()
            time.sleep(speed)
            
            # Clear the line for next iteration
            print("\r" + " " * len(glitched) + "\r", end="")
        
        # Finally print the correct text
        print(f"{color}{text}{RESET}")
    
    def show_network_art(self):
        """Display network ASCII art"""
        print(f"{MATRIX_GREEN}{NETWORK_ART}{RESET}")
    
    def print_cmd_prompt(self, prompt_text="cmd >"):
        """Print the command prompt with retro styling"""
        print(f"{BOLD}{MATRIX_GREEN}{prompt_text}{RESET}", end=" ")
        sys.stdout.flush()

# Create a global instance for easy importing
terminal = TerminalOutput()
