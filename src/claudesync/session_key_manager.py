import subprocess
import base64
import logging
import os
from pathlib import Path
from typing import Optional, Tuple, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SessionKeyManager:
    """Manages session keys using SSH Ed25519 keys for encryption."""

    def __init__(self):
        """
        Initialize the SessionKeyManager.

        Raises:
            RuntimeError: If no valid Ed25519 key can be found or accessed
        """
        self.logger = logging.getLogger(__name__)
        try:
            self.ssh_key_path = self._find_ssh_key()
        except (OSError, RuntimeError) as e:
            self.logger.error(f"Failed to initialize SessionKeyManager: {e}")
            print("\nError: No usable Ed25519 SSH key found.")
            print("\nTo fix this, please:")
            print("1. Run the following command:")
            print('   ssh-keygen -t ed25519 -C "your_email@example.com"')
            print("2. When prompted for the file location, press Enter to use the default")
            print("3. Optionally enter a secure passphrase")
            print("\nIf you already have an Ed25519 key:")
            print("- Check permissions on your .ssh directory (should be 700)")
            print("- Check permissions on your key files (should be 600)")
            print("- Ensure you have read access to the key files")
            raise RuntimeError("No usable Ed25519 SSH key found") from e

    def _scan_ssh_directory(self) -> List[Path]:
        """
        Scans .ssh directory for potential key files.

        Returns:
            List[Path]: List of potential key files

        Raises:
            OSError: If .ssh directory cannot be accessed
        """
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            try:
                ssh_dir.mkdir(mode=0o700)
                self.logger.info("Created .ssh directory with correct permissions")
            except OSError as e:
                self.logger.error(f"Failed to create .ssh directory: {e}")
                raise

        # Check .ssh directory permissions
        try:
            ssh_dir_mode = ssh_dir.stat().st_mode & 0o777
            if ssh_dir_mode != 0o700:
                self.logger.warning(f".ssh directory has incorrect permissions: {oct(ssh_dir_mode)}")
                try:
                    ssh_dir.chmod(0o700)
                    self.logger.info("Fixed .ssh directory permissions")
                except OSError as e:
                    self.logger.error(f"Failed to fix .ssh directory permissions: {e}")
        except OSError as e:
            self.logger.error(f"Cannot check .ssh directory permissions: {e}")
            raise

        return list(ssh_dir.glob("id_*"))

    def _find_ssh_key(self) -> Path:
        """
        Find a valid Ed25519 SSH key.

        Returns:
            Path: Path to the first valid Ed25519 key found

        Raises:
            RuntimeError: If no valid Ed25519 key is found
            OSError: If there are permission issues
        """
        potential_keys = self._scan_ssh_directory()
        ed25519_keys = []

        for key_file in potential_keys:
            if key_file.name.endswith(".pub"):
                continue

            try:
                if not os.access(key_file, os.R_OK):
                    self.logger.warning(f"No read permission for {key_file}")
                    continue

                key_type = self._get_key_type(key_file)
                if key_type == "ed25519":
                    ed25519_keys.append(key_file)

            except (subprocess.CalledProcessError, OSError) as e:
                self.logger.debug(f"Failed to check key {key_file}: {e}")
                continue

        if not ed25519_keys:
            raise RuntimeError("No Ed25519 keys found")

        # Prefer id_ed25519 if it exists, otherwise use the first Ed25519 key found
        default_key = next((k for k in ed25519_keys if k.name == "id_ed25519"), ed25519_keys[0])
        self._verify_key_permissions(default_key)
        return default_key

    def _verify_key_permissions(self, key_path: Path) -> None:
        """
        Verifies and attempts to fix SSH key file permissions.

        Args:
            key_path: Path to the SSH key file

        Raises:
            OSError: If permissions cannot be checked or fixed
        """
        try:
            current_perms = key_path.stat().st_mode & 0o777
            if current_perms != 0o600:
                self.logger.warning(
                    f"SSH key {key_path} has incorrect permissions: {oct(current_perms)}"
                )
                key_path.chmod(0o600)
                self.logger.info(f"Fixed permissions on {key_path}")
        except OSError as e:
            self.logger.error(f"Failed to verify/fix key permissions for {key_path}: {e}")
            raise

    def _get_key_type(self, key_path: Path) -> str:
        """
        Determines the type of SSH key.

        Args:
            key_path: Path to the SSH key file

        Returns:
            str: Key type ('ed25519', 'ecdsa', 'rsa', etc.)

        Raises:
            RuntimeError: If key type cannot be determined
            subprocess.CalledProcessError: If ssh-keygen fails
        """
        try:
            result = subprocess.run(
                ["ssh-keygen", "-l", "-f", str(key_path)],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.lower()

            for key_type in ["ed25519", "ecdsa", "rsa"]:
                if key_type in output:
                    return key_type

            raise RuntimeError(f"Unknown key type in {key_path}")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to determine key type for {key_path}: {e}")
            raise

    def _derive_key_from_ssh_key(self) -> bytes:
        """
        Derives an encryption key from the SSH key.

        Returns:
            bytes: Derived encryption key

        Raises:
            OSError: If the key file cannot be read
        """
        try:
            with open(self.ssh_key_path, "rb") as key_file:
                ssh_key_data = key_file.read()

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"claudesync",
                iterations=100000,
            )
            return base64.urlsafe_b64encode(kdf.derive(ssh_key_data))

        except OSError as e:
            self.logger.error(f"Failed to read SSH key file: {e}")
            raise

    def encrypt_session_key(self, provider: str, session_key: str) -> Tuple[str, str]:
        """
        Encrypts a session key.

        Args:
            provider: Name of the provider
            session_key: Session key to encrypt

        Returns:
            Tuple[str, str]: (encrypted session key, encryption method)

        Raises:
            RuntimeError: If key type is not Ed25519 or encryption fails
        """
        if not session_key:
            raise ValueError("Session key cannot be empty")

        key_type = self._get_key_type(self.ssh_key_path)
        if key_type != "ed25519":
            raise RuntimeError(
                f"SSH key must be Ed25519 type, found {key_type}. "
                "Please generate an Ed25519 key using: ssh-keygen -t ed25519"
            )

        try:
            return self._encrypt_symmetric(session_key)
        except Exception as e:
            self.logger.error(f"Failed to encrypt session key: {e}")
            raise RuntimeError(f"Encryption failed: {e}")

    def _encrypt_symmetric(self, session_key: str) -> Tuple[str, str]:
        """
        Performs symmetric encryption of the session key.

        Args:
            session_key: Session key to encrypt

        Returns:
            Tuple[str, str]: (encrypted session key, encryption method)
        """
        key = self._derive_key_from_ssh_key()
        f = Fernet(key)
        encrypted_session_key = f.encrypt(session_key.encode()).decode()
        return encrypted_session_key, "symmetric"

    def decrypt_session_key(
            self, provider: str, encryption_method: str, encrypted_session_key: str
    ) -> Optional[str]:
        """
        Decrypts a session key.

        Args:
            provider: Name of the provider
            encryption_method: Method used for encryption
            encrypted_session_key: Encrypted session key

        Returns:
            Optional[str]: Decrypted session key or None if decryption fails

        Raises:
            ValueError: If encryption method is unknown or parameters are invalid
            RuntimeError: If key type is not Ed25519 or decryption fails
        """
        if not encrypted_session_key or not encryption_method:
            return None

        key_type = self._get_key_type(self.ssh_key_path)
        if key_type != "ed25519":
            raise RuntimeError(
                f"SSH key must be Ed25519 type, found {key_type}. "
                "Please generate an Ed25519 key using: ssh-keygen -t ed25519"
            )

        if encryption_method != "symmetric":
            raise ValueError(f"Unknown encryption method: {encryption_method}")

        try:
            return self._decrypt_symmetric(encrypted_session_key)
        except Exception as e:
            self.logger.error(f"Failed to decrypt session key: {e}")
            raise RuntimeError(f"Decryption failed: {e}")

    def _decrypt_symmetric(self, encrypted_session_key: str) -> str:
        """
        Performs symmetric decryption of the session key.

        Args:
            encrypted_session_key: Encrypted session key

        Returns:
            str: Decrypted session key
        """
        key = self._derive_key_from_ssh_key()
        f = Fernet(key)
        return f.decrypt(encrypted_session_key.encode()).decode()