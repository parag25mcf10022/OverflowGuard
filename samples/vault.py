import subprocess
import os

class VaultManager:
    def __init__(self):
        self.cmd_executor = getattr(subprocess, 'check_output')

    def sync_backup(self, user_provided_path):
        # OBFUSCATION: Using dynamic attribute access and f-strings 
        # to hide a 'shell=True' OS Injection.
        # Vulnerability: CRITICAL (CWE-78)
        print(f"[*] Synchronizing vault to: {user_provided_path}")
        
        # A malicious input like: "backups; rm -rf /" would trigger this
        try:
            # Bandit will catch this because of shell=True
            logic = f"ls -la {user_provided_path}"
            self.cmd_executor(logic, shell=True)
        except Exception as e:
            pass

if __name__ == "__main__":
    vm = VaultManager()
    # Simulating malicious input
    vm.sync_backup("/tmp/backup_dir; whoami")
