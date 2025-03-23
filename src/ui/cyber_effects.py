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

from .terminal_output import terminal, NEON_GREEN, BRIGHT_GREEN, CYAN_BLUE, RESET, INFO_CYAN, WARNING_RED

# Cyberpunk characters and symbols
CYBER_CHARS = "!@#$%^&*()_+-=[]\\{}|;':\",./<>?`~"

class CyberEffect:
    """Class for creating cyberpunk/hacker-style terminal effects"""
    
    def __init__(self):
        self.console = Console()
    
    def type_text(self, text, speed=0.02, color=NEON_GREEN, jitter=False, newline=True):
        """Type text with a hacker-style animation (using terminal output system)"""
        # Set message type based on color for backward compatibility
        msg_type = "normal"
        if color == INFO_CYAN:
            msg_type = "info"
        elif color == WARNING_RED:
            msg_type = "warning"
        elif color == BRIGHT_GREEN:
            msg_type = "success"
        
        # Use the new terminal output system
        terminal.type_text(text, speed=speed, msg_type=msg_type, jitter=jitter, newline=newline)
    
    def glitch_text(self, text, iterations=3, speed=0.1, color=NEON_GREEN):
        """Create a glitching text effect (always green per requirement)"""
        # Use the new terminal output system (always NEON_GREEN for glitch text)
        terminal.glitch_text(text, iterations=iterations, speed=speed)
    
    @staticmethod
    def display_banner(text, font="cyberlarge", color=NEON_GREEN):
        """Display ASCII art banner"""
        ascii_art = text2art(text, font=font)
        # Use terminal output system instead of direct print
        terminal.print(ascii_art)
    
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
        terminal.print(f"[*] Initializing connection to {target}...", msg_type="normal")
        
        connection_steps = [
            "Establishing secure channel",
            "Bypassing firewall",
            "Negotiating encryption",
            "Validating connection",
            "Finalizing handshake"
        ]
        
        for i, step in enumerate(connection_steps[:steps], 1):
            terminal.print(f"[{i}/{steps}] {step}", msg_type="normal", newline=False)
            
            # Simulate progress with dots
            for _ in range(3):
                time.sleep(0.3)
                terminal.print(".", msg_type="normal", newline=False)
            
            terminal.print(" Complete!", msg_type="success")
            time.sleep(0.2)
        
        terminal.success(f"[+] Connection to {target} established!")
