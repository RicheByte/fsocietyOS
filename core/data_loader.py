"""Data loaders for JSON-based databases used by tools."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional


class DataLoader:
    """Load common data files (wordlists, CVE databases, etc.)"""
    
    DATA_DIR = Path(__file__).parent.parent / "data"
    
    @classmethod
    def load_kernel_exploits(cls) -> List[Dict[str, Any]]:
        """Load kernel exploits database"""
        return cls._load_json("kernel_exploits.json").get("exploits", [])
    
    @classmethod
    def load_service_signatures(cls) -> Dict[str, Any]:
        """Load service vulnerability signatures"""
        return cls._load_json("service_signatures.json").get("services", {})
    
    @classmethod
    def load_wordlists(cls) -> Dict[str, List[str]]:
        """Load common wordlists"""
        data = cls._load_json("common_wordlists.json")
        return {
            "directories": data.get("directories", []),
            "admin_paths": data.get("admin_paths", []),
            "usernames": data.get("usernames", []),
            "passwords": data.get("passwords", [])
        }
    
    @classmethod
    def load_directories(cls) -> List[str]:
        """Load common directory names for fuzzing"""
        return cls._load_json("common_wordlists.json").get("directories", [])
    
    @classmethod
    def load_admin_paths(cls) -> List[str]:
        """Load common admin panel paths"""
        return cls._load_json("common_wordlists.json").get("admin_paths", [])
    
    @classmethod
    def load_usernames(cls) -> List[str]:
        """Load common usernames"""
        return cls._load_json("common_wordlists.json").get("usernames", [])
    
    @classmethod
    def load_passwords(cls) -> List[str]:
        """Load common passwords"""
        return cls._load_json("common_wordlists.json").get("passwords", [])
    
    @classmethod
    def _load_json(cls, filename: str) -> Dict[str, Any]:
        """Load JSON file from data directory"""
        try:
            filepath = cls.DATA_DIR / filename
            if not filepath.exists():
                logging.warning(f"Data file not found: {filepath}")
                return {}
            
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing {filename}: {e}")
            return {}
        except Exception as e:
            logging.error(f"Error loading {filename}: {e}")
            return {}


# Convenience shortcuts
def get_kernel_exploits() -> List[Dict[str, Any]]:
    """Get kernel exploits database"""
    return DataLoader.load_kernel_exploits()


def get_service_signatures() -> Dict[str, Any]:
    """Get service signatures"""
    return DataLoader.load_service_signatures()


def get_wordlists() -> Dict[str, List[str]]:
    """Get all wordlists"""
    return DataLoader.load_wordlists()


def get_directories() -> List[str]:
    """Get common directory names"""
    return DataLoader.load_directories()


def get_admin_paths() -> List[str]:
    """Get common admin panel paths"""
    return DataLoader.load_admin_paths()


def get_common_usernames() -> List[str]:
    """Get common usernames"""
    return DataLoader.load_usernames()


def get_common_passwords() -> List[str]:
    """Get common passwords"""
    return DataLoader.load_passwords()
