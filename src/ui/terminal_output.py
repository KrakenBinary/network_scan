#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import random
from rich.console import Console
from rich.text import Text

# ANSI colors for consistent use throughout the application
NEON_GREEN = "\033[38;2;0;255;0m"
BRIGHT_GREEN = "\033[38;2;50;255;50m"
CYAN_BLUE = "\033[38;2;0;255;255m"
WARNING_RED = "\033[38;2;255;50;50m"
INFO_CYAN = "\033[38;2;0;200;255m"
RESET = "\033[0m"

# Message types for the output manager
MSG_NORMAL = "normal"
MSG_SUCCESS = "success" 
MSG_INFO = "info"
MSG_WARNING = "warning"
MSG_ERROR = "error"

class TerminalOutput:
    """Centralized terminal output manager for consistent UI styling"""
    
    def __init__(self):
        self.console = Console()
    
    def print(self, text, msg_type=MSG_NORMAL, newline=True):
        """Print text to the terminal with appropriate styling"""
        # Determine color based on message type
        if msg_type == MSG_SUCCESS:
            color = BRIGHT_GREEN
        elif msg_type == MSG_INFO:
            color = INFO_CYAN
        elif msg_type == MSG_WARNING or msg_type == MSG_ERROR:
            color = WARNING_RED
        else:
            color = NEON_GREEN
        
        # Print with appropriate styling
        if newline:
            print(f"{color}{text}{RESET}")
        else:
            print(f"{color}{text}{RESET}", end="")
    
    def type_text(self, text, speed=0.02, msg_type=MSG_NORMAL, jitter=False, newline=True):
        """Type text with a hacker-style animation"""
        # Determine color based on message type
        if msg_type == MSG_SUCCESS:
            color = BRIGHT_GREEN
        elif msg_type == MSG_INFO:
            color = INFO_CYAN
        elif msg_type == MSG_WARNING or msg_type == MSG_ERROR:
            color = WARNING_RED
        else:
            color = NEON_GREEN
            
        # For Rich console compatibility, use a simple approach without ANSI codes
        if color == NEON_GREEN:
            rich_color = "bright_green"
        elif color == INFO_CYAN:
            rich_color = "cyan"
        elif color == WARNING_RED:
            rich_color = "red"
        else:
            rich_color = "green"  # Default fallback
            
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
                
            self.console.print(char, style=rich_color, end="")
            sys.stdout.flush()
            time.sleep(delay)
        
        if newline:
            print()
    
    def glitch_text(self, text, iterations=3, speed=0.1, msg_type=MSG_NORMAL):
        """Create a glitching text effect"""
        # Always use NEON_GREEN for glitch text, per requirement
        color = NEON_GREEN
        
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
    
    def separator(self, char='=', length=80, msg_type=MSG_NORMAL):
        """Print a separator line"""
        if msg_type == MSG_SUCCESS:
            color = BRIGHT_GREEN
        elif msg_type == MSG_INFO:
            color = INFO_CYAN
        elif msg_type == MSG_WARNING or msg_type == MSG_ERROR:
            color = WARNING_RED
        else:
            color = NEON_GREEN
            
        print(f"\n{color}{char * length}{RESET}\n")
    
    def info(self, text, typed=False, speed=0.01):
        """Print an information message in cyan"""
        if typed:
            self.type_text(text, speed=speed, msg_type=MSG_INFO)
        else:
            self.print(text, msg_type=MSG_INFO)
    
    def warning(self, text, typed=False, speed=0.01):
        """Print a warning message in red"""
        if typed:
            self.type_text(text, speed=speed, msg_type=MSG_WARNING)
        else:
            self.print(text, msg_type=MSG_WARNING)
    
    def success(self, text, typed=False, speed=0.01):
        """Print a success message in bright green"""
        if typed:
            self.type_text(text, speed=speed, msg_type=MSG_SUCCESS)
        else:
            self.print(text, msg_type=MSG_SUCCESS)
            
    def error(self, text, typed=False, speed=0.01):
        """Print an error message in red"""
        if typed:
            self.type_text(text, speed=speed, msg_type=MSG_ERROR)
        else:
            self.print(text, msg_type=MSG_ERROR)
    
    def prompt(self, text, typed=False, speed=0.01):
        """Print a prompt message and return user input"""
        if typed:
            self.type_text(f"{text}", speed=speed, newline=False)
        else:
            self.print(f"{text}", newline=False)
        return input()

    def table(self, table_object):
        """Print a rich table object through the console"""
        # This method provides consistent handling of rich tables
        self.console.print(table_object)
    
    def rich_print(self, rich_content):
        """Print rich content (tables, panels, etc) through the console"""
        # This method handles any rich content that needs direct console access
        self.console.print(rich_content)
    
# Create a global instance for easy importing
terminal = TerminalOutput()
