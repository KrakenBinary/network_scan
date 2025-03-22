#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import random
from art import text2art
from yaspin import yaspin
from yaspin.spinners import Spinners
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.progress import TaskProgressColumn, TimeRemainingColumn
from rich.console import Console
from rich.text import Text
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# ANSI colors
NEON_GREEN = "\033[38;2;0;255;0m"
BRIGHT_GREEN = "\033[38;2;50;255;50m"
CYAN_BLUE = "\033[38;2;0;255;255m"
TERMINAL_GREEN = "\033[32m"
RESET = "\033[0m"

# Cyberpunk characters and symbols
CYBER_CHARS = "!@#$%^&*()_+-=[]\\{}|;':\",./<>?`~"

class CyberEffect:
    """Class for creating cyberpunk/hacker-style terminal effects"""
    
    def __init__(self):
        self.console = Console()
    
    @staticmethod
    def type_text(text, speed=0.02, color=NEON_GREEN, jitter=False, newline=True):
        """Type text with a hacker-style animation"""
        # For Rich console compatibility, use a simple approach without ANSI codes
        if color == NEON_GREEN:
            rich_color = "bright_green"
        elif color == CYAN_BLUE:
            rich_color = "cyan"
        else:
            rich_color = "green"  # Default fallback
            
        console = Console()
        
        for char in text:
            if jitter and random.random() < 0.05:
                # Simulate typing errors and corrections
                typo = random.choice("qwertyuiopasdfghjklzxcvbnm")
                console.print(typo, style=rich_color, end="")
                sys.stdout.flush()
                time.sleep(speed * 2)
                console.print("\b", end="")
            
            # Randomize typing speed if jitter is enabled
            delay = speed
            if jitter:
                delay = speed * random.uniform(0.5, 1.5)
                
            console.print(char, style=rich_color, end="")
            sys.stdout.flush()
            time.sleep(delay)
        
        if newline:
            print()
    
    @staticmethod
    def glitch_text(text, iterations=3, speed=0.1, color=NEON_GREEN):
        """Create a glitching text effect"""
        glitch_chars = "!@#$%^&*()_+-=[]\\{}|;':\",./<>?`~"
        
        for _ in range(iterations):
            glitched_text = ""
            for char in text:
                if random.random() < 0.3 and char != " ":
                    glitched_text += random.choice(glitch_chars)
                else:
                    glitched_text += char
            
            sys.stdout.write("\r" + color + glitched_text + RESET)
            sys.stdout.flush()
            time.sleep(speed)
        
        # Show final clean text
        sys.stdout.write("\r" + color + text + RESET + "\n")
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
            TextColumn(f"[bright_green]{task_description}"),
            BarColumn(bar_width=40, style="bright_green", complete_style="green"),
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
