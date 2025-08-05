from categories.recon.methods_recon.digital_fingerprinting.find_ports import PortScan
from ftplib import FTP,error_perm, all_errors, FTP_TLS
import argparse
import getpass
import io
from time import sleep

class Configuration_checker:
    @staticmethod
    def run(ip, timeout, retries):
        misconfigs = {}

        scan_results = PortScan.Scan_method_handler(ip, tcp_flags=None, timeout=timeout, retries=retries)

    @staticmethod
    def FTP_misconfigs(ip, port, timeout, retries, misconfigs):
        service = "ftp"
        if service not in misconfigs:
            misconfigs[service] = {}

        category = "authentication and access control misconfigurations"
        if category not in misconfigs[service]:
            misconfigs[service][category] = []

        service_misconfigs = misconfigs[service][category]
        service_misconfigs = Configuration_checker.anonymous_auth_msconf(service_misconfigs, ip, port, timeout)

        category = "Weak Authentication"
        if category not in misconfigs[service]:
            misconfigs[service][category] = []
        
        service_misconfigs = misconfigs[service][category]
        service_misconfigs = Configuration_checker.weak_authentication(service_misconfigs, ip, port, timeout)
        service_misconfigs = Configuration_checker.no_account_lockout_policy(service_misconfigs, ip, port, timeout)
        service_misconfigs = Configuration_checker.plaintext_authentication_missing_mfa(service_misconfigs, ip, port, timeout) 

        category = "Encryption and Data Issues"
        if category not in misconfigs[service]:
            misconfigs[service][category] = []
        
        service_misconfigs = misconfigs[service][category]
        service_misconfigs = Configuration_checker.check_ftp_encryption(service_misconfigs, ip, port, timeout)
        service_misconfigs = Configuration_checker.unencrypted_file_transfer(service_misconfigs, ip, port, timeout)

        category = "Directory and File System Misconfigurations"
        if category not in misconfigs[service]:
            misconfigs[service][category] = []
        
        service_misconfigs = misconfigs[service][category]
        service_misconfigs = Configuration_checker.check_ftp_directory_traversal(service_misconfigs, ip, port, timeout)
        service_misconfigs = Configuration_checker.check_world_writable_dirs(service_misconfigs, ip, port, timeout)
        return misconfigs

    @staticmethod
    def _credentials_try(ip, port, timeout):
        try:
            ftp = FTP()
            ftp.connect(host=ip, port=port, timeout=timeout)
            ftp.login(user='anonymous', passwd='anonymous@example.com')
            return ftp
        except (error_perm, OSError):
            pass

        for username, password in COMMON_CREDENTIALS + DEFAULT_CREDENTIALS:
            try:
                ftp = FTP()
                ftp.connect(host=ip, port=port, timeout=timeout)
                ftp.login(user=username, passwd=password)
                return ftp
            except (error_perm, OSError):
                continue

        return None

    @staticmethod
    def _safe_ftp_connect(ip, port, timeout):
        """Helper method to safely create FTP connection"""
        try:
            ftp = FTP()
            ftp.connect(host=ip, port=port, timeout=timeout)
            return ftp
        except Exception:
            return None
    
    @staticmethod
    def _safe_ftp_close(ftp):
        """Helper method to safely close FTP connection"""
        if ftp:
            try:
                ftp.quit()
            except:
                try:
                    ftp.close()
                except:
                    pass

    @staticmethod
    def anonymous_auth_msconf(service_misconfigs, ip, port, timeout):
        ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        logged_in = False
        user_type = None

        try:
            ftp.login(user='anonymous', passwd='anonymous@example.com')
            service_misconfigs.append("Anonymous authentication allowed with username 'anonymous'")
            logged_in = True
            user_type = "anonymous"
        except (error_perm, OSError):
            for username, password in COMMON_CREDENTIALS + DEFAULT_CREDENTIALS:
                try:
                    ftp.login(user=username, passwd=password)
                    logged_in = True
                    user_type = f"{username}:{password}"
                    break
                except (error_perm, OSError):
                    continue

        if not logged_in:
            Configuration_checker._safe_ftp_close(ftp)
            return service_misconfigs

        try:
            try:
                ftp.storbinary("STOR test_upload.txt", io.BytesIO(b"test"))
                service_misconfigs.append(f"{user_type} has write access (test_upload.txt)")
                ftp.delete("test_upload.txt")
            except (error_perm, OSError):
                pass

            for dir in WEB_DIRS:
                try:
                    ftp.cwd(dir)
                    fake_malicious_file = io.BytesIO(b"<?php echo 'hacked'; ?>")
                    filename = "test_shell.php"
                    ftp.storbinary(f"STOR {filename}", fake_malicious_file)
                    service_misconfigs.append(f"{user_type} uploaded PHP shell in {dir}")
                    ftp.delete(filename)
                except (error_perm, OSError):
                    continue

            for dir in SENSITIVE_DIRS:
                perms = []
                try:
                    ftp.cwd(dir)
                    test_data = io.BytesIO(b"test")
                    ftp.storbinary("STOR write_test.txt", test_data)
                    perms.append("write")
                    ftp.delete("write_test.txt")
                    perms.append("delete")
                    ftp.mkd("testdir")
                    perms.append("mkdir")
                    ftp.rmd("testdir")
                    if perms:
                        service_misconfigs.append(f"{user_type} has {perms} permissions in {dir}")
                except (error_perm, OSError):
                    continue

            for system_dir in SYSTEM_DIRS:
                try:
                    ftp.cwd(system_dir)
                    service_misconfigs.append(f"{user_type} can access system directory: {system_dir}")
                except (error_perm, OSError):
                    continue

            for dir in SENSITIVE_DIRS:
                try:
                    ftp.cwd(dir)
                    service_misconfigs.append(f"{user_type} can access sensitive directory: {dir}")
                    try:
                        listed_files = ftp.nlst()
                    except (error_perm, OSError):
                        listed_files = []

                    for file in listed_files:
                        try:
                            ftp.retrbinary(f"RETR {file}", lambda _: None)
                            service_misconfigs.append(f"{user_type} downloaded file from: {dir}{file}")
                        except (error_perm, OSError):
                            continue

                    for file in SENSITIVE_FILES:
                        try:
                            ftp.retrbinary(f"RETR {file}", lambda _: None)
                            service_misconfigs.append(f"{user_type} downloaded sensitive file: {dir}{file}")
                        except (error_perm, OSError):
                            continue

                except (error_perm, OSError):
                    continue

        finally:
            Configuration_checker._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def weak_authentication(service_misconfigs, ip, port, timeout):
        consecutive_failures = 0
        max_consecutive_failures = 5
        
        for username, password in COMMON_CREDENTIALS:
            if consecutive_failures >= max_consecutive_failures:
                break
                
            ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
            if not ftp:
                consecutive_failures += 1
                sleep(DELAY)
                continue
                
            try:
                ftp.login(user=username, passwd=password)

                msg = f"Allowed Login with weak credentials: {username}, {password}"
                if (username, password) in DEFAULT_CREDENTIALS:
                    msg += " — Default credentials still in use"

                service_misconfigs.append(msg)
                consecutive_failures = 0
            except (error_perm, OSError):
                consecutive_failures += 1
            except all_errors:
                consecutive_failures += 1
            finally:
                Configuration_checker._safe_ftp_close(ftp)
                sleep(DELAY)

        consecutive_failures = 0
        test_user = "admin"
        weak_passwords = ["123456", "password", "admin", "ftp", "test", "root"]

        for pwd in weak_passwords:
            if consecutive_failures >= max_consecutive_failures:
                break
                
            ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
            if not ftp:
                consecutive_failures += 1
                sleep(DELAY)
                continue
                
            try:
                ftp.login(user=test_user, passwd=pwd)
                service_misconfigs.append(f"Allowed weak password '{pwd}' for user '{test_user}' — password complexity missing")
                consecutive_failures = 0
                Configuration_checker._safe_ftp_close(ftp)
                break
            except (error_perm, OSError):
                consecutive_failures += 1
            except all_errors:
                consecutive_failures += 1
                break
            finally:
                Configuration_checker._safe_ftp_close(ftp)
                sleep(DELAY)

        return service_misconfigs

    @staticmethod
    def plaintext_authentication_missing_mfa(service_misconfigs, ip, port, timeout):
        ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
        if ftp:
            Configuration_checker._safe_ftp_close(ftp)
            service_misconfigs.append(f"FTP service on {ip}:{port} uses plaintext authentication (unencrypted login over FTP)")
            service_misconfigs.append(f"FTP service at {ip}:{port} does not enforce multi-factor authentication (MFA)")

        return service_misconfigs

    @staticmethod
    def no_account_lockout_policy(service_misconfigs, ip, port, timeout, max_attempts=10):
        test_username = "nonexistent_user"
        test_password = "wrong_password"

        consecutive_failures = 0

        for attempt in range(max_attempts):
            ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
            if not ftp:
                break
                
            try:
                ftp.login(user=test_username, passwd=test_password)
            except (error_perm, OSError):
                consecutive_failures += 1
            except all_errors:
                break
            finally:
                Configuration_checker._safe_ftp_close(ftp)
                sleep(DELAY)

        if consecutive_failures == max_attempts:
            service_misconfigs.append(f"No account lockout policy detected after {max_attempts} failed login attempts")

        return service_misconfigs

    @staticmethod
    def check_ftp_encryption(service_misconfigs, ip, port, timeout):
        try:
            ftps = FTP_TLS()
            ftps.connect(ip, port, timeout=timeout)
            
            auth_supported = True
            try:
                ftps.auth()
            except (error_perm, OSError, all_errors):
                auth_supported = False
                service_misconfigs.append(f"Control channel NOT encrypted on port {port} (AUTH TLS missing)")

            if auth_supported:
                try:
                    ftps.prot_p()
                except (error_perm, OSError, all_errors):
                    service_misconfigs.append(f"Data channel NOT encrypted on port {port} (PROT P missing)")
            try:
                ftps.quit()
            except:
                try:
                    ftps.close()
                except:
                    pass
                    
        except (OSError, TimeoutError, all_errors):
            ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
            if ftp:
                Configuration_checker._safe_ftp_close(ftp)
                service_misconfigs.append("FTP server does NOT support FTPS (FTP over SSL/TLS) — no encryption available")
            else:
                service_misconfigs.append(f"Failed to connect to FTP server on port {port} — encryption check skipped")

        return service_misconfigs

    @staticmethod
    def unencrypted_file_transfer(service_misconfigs, ip, port, timeout):
        if port != 21:
            return service_misconfigs
        
        ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
        if ftp:
            try:
                ftp.login()
                service_misconfigs.append("FTP server on port 21 allows unencrypted file transfers (plaintext data and credentials).")
            except (error_perm, OSError):
                pass
            finally:
                Configuration_checker._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def check_ftp_directory_traversal(service_misconfigs, ip, port, timeout):
        ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        logged_in = False
        user_type = None

        try:
            ftp.login(user='anonymous', passwd='anonymous@example.com')
            logged_in = True
            user_type = 'anonymous'
        except (error_perm, OSError):
            for username, password in COMMON_CREDENTIALS + DEFAULT_CREDENTIALS:
                try:
                    ftp.login(user=username, passwd=password)
                    logged_in = True
                    user_type = f'{username}:{password}'
                    break
                except (error_perm, OSError):
                    continue

        if not logged_in:
            Configuration_checker._safe_ftp_close(ftp)
            return service_misconfigs

        try:
            original_dir = ftp.pwd()
            traversal_attempts = ['..', '../..', '../../..', '../../../..', '../../../../..']

            for path in traversal_attempts:
                try:
                    ftp.cwd(path)
                    new_dir = ftp.pwd()
                    if new_dir != original_dir:
                        service_misconfigs.append(f"Directory traversal possible by {user_type} — able to escape FTP root with '{path}'")
                        service_misconfigs.append("FTP server lacks path validation — user able to access unintended directories")
                        try:
                            listed_files = ftp.nlst()
                        except (error_perm, OSError):
                            listed_files = []

                        for file in listed_files:
                            try:
                                ftp.retrbinary(f"RETR {file}", lambda _: None)
                                service_misconfigs.append(f"File access allowed to {user_type} outside FTP directory: {new_dir}{file}")
                            except (error_perm, OSError):
                                continue
                        break
                except (error_perm, OSError):
                    continue
        finally:
            Configuration_checker._safe_ftp_close(ftp)

        return service_misconfigs


    @staticmethod
    def check_world_writable_dirs(service_misconfigs, ip, port, timeout):
        ftp = Configuration_checker._safe_ftp_connect(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        logged_in = False
        user_type = None

        try:
            # Try anonymous login
            ftp.login(user='anonymous', passwd='anonymous@example.com')
            logged_in = True
            user_type = 'anonymous'
        except (error_perm, OSError):
            for username, password in COMMON_CREDENTIALS + DEFAULT_CREDENTIALS:
                try:
                    ftp.login(user=username, passwd=password)
                    logged_in = True
                    user_type = f'{username}:{password}'
                    break
                except (error_perm, OSError):
                    continue

        if not logged_in:
            Configuration_checker._safe_ftp_close(ftp)
            return service_misconfigs

        try:
            directories_to_check = SENSITIVE_DIRS + WEB_DIRS
            for dir in directories_to_check:
                try:
                    ftp.cwd(dir)
                    filename = "writetest.txt"
                    data = io.BytesIO(b"test")
                    ftp.storbinary(f"STOR {filename}", data)
                    ftp.delete(filename)
                    service_misconfigs.append(f"World-writable directory found: {dir} — writable by {user_type}")
                except (error_perm, OSError):
                    continue
        finally:
            Configuration_checker._safe_ftp_close(ftp)

        return service_misconfigs

DELAY = 2
COMMON_CREDENTIALS = [
    ("anonymous", ""),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("user", "password"),
    ("test", "test"),
    ("root", "root"),
    ("guest", "guest"),
    ("anonymous", "anonymous@domain.com")
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("ftp", "ftp"),
    ("user", "password"),
    ("test", "test"),
    ("root", "root"),
    ("guest", "guest"),
]

SYSTEM_DIRS = [
    '/etc/',
    '/bin/',
    '/sbin/',
    '/usr/',
    '/usr/local/',
    '/usr/bin/',
    '/lib/',
    '/lib64/',
    '/root/',
    '/var/log/',
    '/boot/',
    '/opt/',
    '/proc/',
    '/dev/',
    '/sys/',
    'C:/Windows/System32/',
    'C:/Program Files/',
    'C:/Program Files (x86)/',
    'C:/Users/',
]


WEB_DIRS = [
    '/www/',
    '/htdocs/',
    '/public_html/',
    '/wwwroot/',
    '/web/',
    '/webroot/',
    '/site/',
    '/sites/',
    '/html/',
    '/httpdocs/',
    '/www-data/',
    '/var/www/',
    '/var/www/html/',
    '/var/www/public_html/',
]

SENSITIVE_DIRS = [
    '/',
    '/etc/',
    '/config/',
    '/configs/',
    '/admin/',
    '/administrator/',
    '/private/',
    '/backup/',
    '/backups/',
    '/db_backup/',
    '/database/',
    '/databases/',
    '/tmp/',
    '/temp/',
    '/logs/',
    '/log/',
    '/var/',
    '/var/log/',
    '/www/',
    '/wwwroot/',
    '/public_html/',
    '/htdocs/',
    '/conf/',
    '/secret/',
    '/secrets/',
    '/credentials/',
    '/.ssh/',
    '/.git/',
    '/.env/',
    '/scripts/',
    '/bin/',
    '/usr/',
    '/usr/local/',
]

SENSITIVE_FILES = [
    'config.php',
    'config.ini',
    'config.json',
    'config.yaml',
    'config.yml',
    '.env',
    '.htaccess',
    'web.config',
    'database.sql',
    'db_backup.sql',
    'backup.sql',
    'passwords.txt',
    'passwd',
    'shadow',
    'id_rsa',
    'id_rsa.pub',
    'authorized_keys',
    'secret.txt',
    'secrets.txt',
    'credentials.txt',
    'users.txt',
    'wp-config.php',
    'settings.py',
    'appsettings.json',
    'config.xml',
    'local.settings.json',
    'docker-compose.yml',
    'docker-compose.yaml',
    'dockerfile',
    'backup.zip',
    'backup.tar.gz',
    'backup.tar',
    'dump.sql',
    'private.key',
    'server.key',
    'server.crt',
    'ssl.key',
    'ssl.crt',
]