"""Stealth and rate-limiting controls for fsociety-reborn tools."""

import time
import random
from typing import Dict


class StealthController:
    """
    Manages request rate limiting and stealth profiles to avoid detection.
    Inspired by Nmap's timing templates.
    """
    
    PROFILES = {
        'paranoid': {
            'delay': 5.0,
            'jitter': 3.0,
            'threads': 1,
            'description': 'Maximum stealth - very slow'
        },
        'sneaky': {
            'delay': 2.0,
            'jitter': 1.0,
            'threads': 2,
            'description': 'High stealth - slow'
        },
        'normal': {
            'delay': 0.5,
            'jitter': 0.2,
            'threads': 10,
            'description': 'Balanced (default)'
        },
        'aggressive': {
            'delay': 0.05,
            'jitter': 0.02,
            'threads': 50,
            'description': 'Fast scanning'
        },
        'insane': {
            'delay': 0,
            'jitter': 0,
            'threads': 100,
            'description': 'Maximum speed'
        },
    }
    
    def __init__(self, profile: str = 'normal'):
        """
        Initialize stealth controller with a profile.
        
        Args:
            profile (str): One of 'paranoid', 'sneaky', 'normal', 'aggressive', 'insane'
        
        Raises:
            ValueError: If profile is not recognized
        """
        if profile not in self.PROFILES:
            valid = ', '.join(self.PROFILES.keys())
            raise ValueError(f"Invalid profile '{profile}'. Valid options: {valid}")
        
        self.profile = profile
        self.config = self.PROFILES[profile]
        self.total_requests = 0
        self.total_wait_time = 0.0
    
    def wait(self, request_count: int = 1) -> None:
        """
        Wait according to stealth profile before making request(s).
        
        Args:
            request_count (int): Number of requests about to be made
        """
        delay = self.config['delay'] * request_count
        jitter = random.uniform(0, self.config['jitter'] * request_count)
        total_wait = delay + jitter
        
        if total_wait > 0:
            time.sleep(total_wait)
            self.total_wait_time += total_wait
    
    def get_thread_count(self) -> int:
        """Get recommended thread count for this profile."""
        return self.config['threads']
    
    def get_config(self) -> Dict:
        """Get full configuration for this profile."""
        return self.config.copy()
    
    def get_description(self) -> str:
        """Get human-readable description of profile."""
        return self.config['description']
    
    @staticmethod
    def list_profiles() -> str:
        """Return formatted list of available profiles."""
        output = "Available Stealth Profiles:\n"
        for name, config in StealthController.PROFILES.items():
            output += f"  {name:12} - {config['description']}\n"
            output += f"    Delay: {config['delay']}s, Jitter: {config['jitter']}s, Threads: {config['threads']}\n"
        return output
