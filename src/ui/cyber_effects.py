#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import random
from yaspin import yaspin
from yaspin.spinners import Spinners
from rich.console import Console
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    SpinnerColumn
)
from rich.text import Text
from art import text2art
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Custom neon green colors
NEON_GREEN = "\033[38;2;0;255;0m"
BRIGHT_GREEN = "\033[38;2;50;255;50m"
CYAN_BLUE = "\033[38;2;0;255;255m"
TERMINAL_GREEN = "\033[32m"
RESET = "\033[0m"

class CyberEffect:
    """Class for creating cyberpunk/hacker-style terminal effects"""
    
    def __init__(self):
        self.console = Console()
    
    @staticmethod
    def type_text(text, speed=0.02, color=NEON_GREEN, jitter=False, newline=True):
        """Type text with a hacker-style animation"""
        for char in text:
            if jitter and random.random() < 0.05:
                # Simulate typing errors and corrections
                typo = random.choice("qwertyuiopasdfghjklzxcvbnm")
                sys.stdout.write(color + typo + "\b" + RESET)
                sys.stdout.flush()
                time.sleep(speed * 2)
            
            # Randomize typing speed if jitter is enabled
            delay = speed
            if jitter:
                delay = speed * random.uniform(0.5, 1.5)
                
            sys.stdout.write(color + char + RESET)
            sys.stdout.flush()
            time.sleep(delay)
        
        if newline:
            print()
    
    @staticmethod
    def glitch_text(text, iterations=3, speed=0.1):
        """Create a glitching text effect"""
        glitch_chars = "!@#$%^&*()_+-=[]\\{}|;':\",./<>?`~"
        
        for _ in range(iterations):
            glitched_text = ""
            for char in text:
                if random.random() < 0.3 and char != " ":
                    glitched_text += random.choice(glitch_chars)
                else:
                    glitched_text += char
            
            sys.stdout.write("\r" + NEON_GREEN + glitched_text + RESET)
            sys.stdout.flush()
            time.sleep(speed)
        
        # Show final clean text
        sys.stdout.write("\r" + NEON_GREEN + text + RESET + "\n")
        sys.stdout.flush()
    
    @staticmethod
    def display_banner(text, font="cyberlarge", color=NEON_GREEN):
        """Display ASCII art banner"""
        ascii_art = text2art(text, font=font)
        print(color + ascii_art + RESET)
    
    @staticmethod
    def hacker_spinner(text="Processing", color=NEON_GREEN):
        """Create a hacker-style spinner"""
        spinner = yaspin(Spinners.dots, text=f"{color}{text}{RESET}")
        return spinner
    
    def cyber_progress(self, task_description="Scanning", total=100):
        """Create a cyberpunk-style progress bar"""
        progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn(f"[{BRIGHT_GREEN}]{task_description}"),
            BarColumn(bar_width=40, style=BRIGHT_GREEN, complete_style=NEON_GREEN),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=self.console
        )
        return progress
    
    @staticmethod
    def simulate_connection(target="127.0.0.1", steps=5):
        """Simulate connecting to a target with hacker aesthetic"""
        print(f"{NEON_GREEN}[*] Initializing connection to {CYAN_BLUE}{target}{NEON_GREEN}...{RESET}")
        
        connection_steps = [
            "Establishing secure channel",
            "Bypassing firewall",
            "Negotiating encryption",
            "Validating connection",
            "Finalizing handshake"
        ]
        
        for i, step in enumerate(connection_steps[:steps], 1):
            sys.stdout.write(f"{NEON_GREEN}[{i}/{steps}] {step}")
            sys.stdout.flush()
            
            # Simulate progress with dots
            for _ in range(3):
                time.sleep(0.3)
                sys.stdout.write(".")
                sys.stdout.flush()
            
            sys.stdout.write(" Complete!\n")
            time.sleep(0.2)
        
        print(f"{NEON_GREEN}[+] Connection to {CYAN_BLUE}{target}{NEON_GREEN} established!{RESET}")
    
    @staticmethod
    def matrix_rain(duration=3, density=0.2):
        """Create a brief matrix-style digital rain effect"""
        try:
            import shutil
            columns, rows = shutil.get_terminal_size()
            
            # Initialize the terminal with blank spaces
            matrix = [" " for _ in range(columns)]
            
            start_time = time.time()
            while time.time() - start_time < duration:
                # Update matrix rain
                for i in range(columns):
                    if matrix[i] == " ":
                        # Start a new drop at random
                        if random.random() < density * 0.1:
                            matrix[i] = random.choice("01")
                    else:
                        # Continue or end existing drop
                        if random.random() < 0.3:
                            matrix[i] = " "
                        else:
                            matrix[i] = random.choice("01")
                
                # Print the current state
                matrix_line = "".join(matrix)
                sys.stdout.write("\r" + NEON_GREEN + matrix_line + RESET)
                sys.stdout.flush()
                time.sleep(0.05)
            
            # Clear the line
            sys.stdout.write("\r" + " " * columns + "\r")
            sys.stdout.flush()
            
        except Exception:
            # Fallback if terminal size detection fails
            pass
