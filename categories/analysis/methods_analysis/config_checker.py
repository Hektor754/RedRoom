from categories.recon.methods_recon.digital_fingerprinting.find_ports import PortScan
from ftplib import FTP, error_perm, all_errors, FTP_TLS, error_temp, error_reply
import io
from time import sleep
import time
import socket
import re
import paramiko

# ===================== CONFIGURABLE CONSTANTS =====================
DELAY = 2
MAX_CONSECUTIVE_FAILURES = 5
MAX_CONCURRENT_CONNECTIONS = 15
DEFAULT_SLEEP_DURATION = 120  # For idle timeout check
TRANSFER_TIMEOUT = 10  # Seconds for file upload/download ops

WEAK_PASSWORDS = [
    "",
    "root",
    "admin",
    "123456",
    "12345678",
    "123456789",
    "password",
    "toor",
    "qwerty",
    "letmein",
    "welcome",
    "1234",
    "111111",
    "123123",
    "abc123",
    "1q2w3e4r",
    "monkey",
    "dragon",
    "passw0rd",
    "iloveyou"
]

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
    '/etc/', '/bin/', '/sbin/', '/usr/', '/usr/local/', '/usr/bin/',
    '/lib/', '/lib64/', '/root/', '/var/log/', '/boot/', '/opt/',
    '/proc/', '/dev/', '/sys/', 'C:/Windows/System32/',
    'C:/Program Files/', 'C:/Program Files (x86)/', 'C:/Users/',
]

WEB_DIRS = [
    '/www/', '/htdocs/', '/public_html/', '/wwwroot/', '/web/',
    '/webroot/', '/site/', '/sites/', '/html/', '/httpdocs/',
    '/www-data/', '/var/www/', '/var/www/html/', '/var/www/public_html/',
]

SENSITIVE_DIRS = [
    '/', '/etc/', '/config/', '/configs/', '/admin/', '/administrator/',
    '/private/', '/backup/', '/backups/', '/db_backup/', '/database/',
    '/databases/', '/tmp/', '/temp/', '/logs/', '/log/', '/var/',
    '/var/log/', '/www/', '/wwwroot/', '/public_html/', '/htdocs/',
    '/conf/', '/secret/', '/secrets/', '/credentials/', '/.ssh/',
    '/.git/', '/.env/', '/scripts/', '/bin/', '/usr/', '/usr/local/',
]

SENSITIVE_FILES = [
    'config.php', 'config.ini', 'config.json', 'config.yaml', 'config.yml',
    '.env', '.htaccess', 'web.config', 'database.sql', 'db_backup.sql',
    'backup.sql', 'passwords.txt', 'passwd', 'shadow', 'id_rsa', 'id_rsa.pub',
    'authorized_keys', 'secret.txt', 'secrets.txt', 'credentials.txt', 'users.txt',
    'wp-config.php', 'settings.py', 'appsettings.json', 'config.xml',
    'local.settings.json', 'docker-compose.yml', 'docker-compose.yaml',
    'dockerfile', 'backup.zip', 'backup.tar.gz', 'backup.tar', 'dump.sql',
    'private.key', 'server.key', 'server.crt', 'ssl.key', 'ssl.crt',
]

GENERAL_LOGS = [
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/ftp.log",
    "/var/log/xferlog",
    "/var/log/vsftpd.log",
    "/var/log/daemon.log",
]

FAILED_LOGIN_LOGS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/faillog",
    "/var/log/btmp",
    "/var/log/wtmp",
]

FILE_TRANSFER_LOGS = [
    "/var/log/xferlog",
    "/var/log/vsftpd.log",
    "/var/log/ftp.log",
    "/var/log/messages",
]

LATEST_VERSIONS = {
    "vsftpd": "3.0.5",
    "proftpd": "1.3.8",
    "pure-ftpd": "1.0.50",
    "wu-ftpd": "2.6.2",
    "filezilla": "1.6.7"
}

EOL_FTP_VERSIONS = {
    "wu-ftpd": "2.6.2",
    "netware ftp": None,
    "serv-u": "15.1.7",
    "guildftpd": "0.999.14",
    "war-ftpd": "1.82",
}

DEFAULT_FTP_BANNERS = [
    "vsftpd 3.0.3",    
    "pure-ftpd",       
    "proftpd",         
    "filezilla server",
    "serv-u",          
]


class Configuration_checker:
    # --------------------- Entry point ---------------------
    @staticmethod
    def run(ip, timeout, retries):
        """
        Placeholder orchestrator. Calls port discovery and returns a misconfigs dict.
        TODO: orchestrate based on scan_results (which ports/services are open).
        """
        misconfigs = {}
        scan_results = PortScan.Scan_method_handler(ip, tcp_flags=None, timeout=timeout, retries=retries)
        # TODO: pick services from scan_results and call appropriate checkers
        return misconfigs

class FTP_Misconfigs:
    
    # --------------------- Core helpers ---------------------
    @staticmethod
    def _safe_ftp_connect(ip, port, timeout):
        """Attempt to connect once and return FTP object or None."""
        try:
            ftp = FTP()
            ftp.connect(host=ip, port=port, timeout=timeout)
            return ftp
        except Exception:
            return None

    @staticmethod
    def _safe_ftp_close(ftp):
        """Safely close/quit FTP connection if present."""
        if ftp:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass

    @staticmethod
    def _login_with_known_creds(ip, port, timeout):
        """
        Attempt login with: anonymous, then COMMON_CREDENTIALS+DEFAULT_CREDENTIALS.
        Returns (ftp, user_type) or (None, None).
        """
        ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
        if not ftp:
            return None, None

        # Try anonymous first
        try:
            ftp.login(user='anonymous', passwd='anonymous@example.com')
            return ftp, "anonymous"
        except (error_perm, OSError):
            pass

        # Try known credentials
        for username, password in COMMON_CREDENTIALS + DEFAULT_CREDENTIALS:
            try:
                ftp.login(user=username, passwd=password)
                return ftp, f"{username}:{password}"
            except (error_perm, OSError):
                continue

        # Nothing worked
        FTP_Misconfigs._safe_ftp_close(ftp)
        return None, None

    @staticmethod
    def _with_transfer_timeout(fn, *args, **kwargs):
        """
        Helper wrapper for operations that perform transfers. It sets a
        temporary default socket timeout during the operation and restores it.
        `fn` must be a callable that performs the transfer operation.
        """
        prev_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(TRANSFER_TIMEOUT)
        try:
            return fn(*args, **kwargs)
        finally:
            socket.setdefaulttimeout(prev_timeout)

    @staticmethod
    def _test_directory_write(ftp, directory, user_type, service_misconfigs):
        """
        Attempt to write and delete a small file in `directory`. Logs to
        service_misconfigs if successful. Non-fatal on failure.
        """
        try:
            ftp.cwd(directory)
        except (error_perm, OSError):
            return

        def _do_write():
            filename = "writetest.txt"
            data = io.BytesIO(b"test")
            ftp.storbinary(f"STOR {filename}", data)
            ftp.delete(filename)

        try:
            FTP_Misconfigs._with_transfer_timeout(_do_write)
            service_misconfigs.append(
                f"World-writable directory found: {directory} — writable by {user_type}"
            )
        except (error_perm, OSError, all_errors):
            # permission denied or transfer error - ignore
            pass
        
    # --------------------- FTP orchestrator ---------------------
    @staticmethod
    def FTP_misconfigs(ip, port, timeout, misconfigs):
        """
        Populate misconfigs[service][category] lists for the FTP service.
        """
        service = "ftp"
        if service not in misconfigs:
            misconfigs[service] = {}

        def ensure_category(cat):
            if cat not in misconfigs[service]:
                misconfigs[service][cat] = []
            return misconfigs[service][cat]

        ensure_category("Authentication and Access Control")
        FTP_Misconfigs.anonymous_auth_msconf(misconfigs[service]["Authentication and Access Control"],ip, port, timeout)

        ensure_category("Weak Authentication")
        FTP_Misconfigs.weak_authentication(misconfigs[service]["Weak Authentication"], ip, port, timeout)
        FTP_Misconfigs.no_account_lockout_policy(misconfigs[service]["Weak Authentication"], ip, port, timeout)
        FTP_Misconfigs.plaintext_authentication_missing_mfa(misconfigs[service]["Weak Authentication"], ip, port, timeout)

        ensure_category("Encryption and Data Issues")
        FTP_Misconfigs.check_ftp_encryption(misconfigs[service]["Encryption and Data Issues"], ip, port, timeout)
        FTP_Misconfigs.unencrypted_file_transfer(misconfigs[service]["Encryption and Data Issues"], ip, port, timeout)

        ensure_category("Directory and File System Misconfigurations")
        FTP_Misconfigs.check_ftp_directory_traversal(misconfigs[service]["Directory and File System Misconfigurations"], ip, port, timeout)
        FTP_Misconfigs.check_world_writable_dirs(misconfigs[service]["Directory and File System Misconfigurations"], ip, port, timeout)

        ensure_category("Server Configuration Issues")
        FTP_Misconfigs.excessive_privilages(misconfigs[service]["Server Configuration Issues"], ip, port, timeout)
        FTP_Misconfigs.check_unnecessary_ftp_features(misconfigs[service]["Server Configuration Issues"], ip, port, timeout)
        FTP_Misconfigs.check_no_connection_limits(misconfigs[service]["Server Configuration Issues"], ip, port, timeout)
        FTP_Misconfigs.check_missing_timeout(misconfigs[service]["Server Configuration Issues"], ip, port, timeout)
        FTP_Misconfigs.check_insufficient_logging(misconfigs[service]["Server Configuration Issues"], ip, port, timeout)
        FTP_Misconfigs.check_failed_login_logging(misconfigs[service]["Server Configuration Issues"], ip, port, timeout)
        
        ensure_category("Network and Protocol Vulnerabilities")
        FTP_Misconfigs.check_passive_mode_insecure_ports(misconfigs[service]["Network and Protocol Vulnerabilities"], ip, port, timeout)
        FTP_Misconfigs.check_active_mode_insecure_behavior(misconfigs[service]["Network and Protocol Vulnerabilities"], ip, port, timeout)

        ensure_category("Operation Security Issues")
        FTP_Misconfigs.check_outdated_ftp_version(misconfigs[service]["Operation Security Issues"], ip, port, timeout)
        FTP_Misconfigs.check_eol_ftp_version(misconfigs[service]["Operation Security Issues"], ip, port, timeout)
        return misconfigs
        
    # --------------------- Individual checks ---------------------
    @staticmethod
    def anonymous_auth_msconf(service_misconfigs, ip, port, timeout):
        """
        Check for anonymous authentication + ability to upload / read sensitive files, etc.
        Uses _login_with_known_creds because the original logic tries anonymous then other creds.
        """
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        # If user_type is "anonymous", we already know anonymous is allowed
        if user_type == "anonymous":
            service_misconfigs.append("Anonymous authentication allowed with username 'anonymous'")

        try:
            # test a simple upload/delete (storbinary + delete)
            def _upload_test():
                ftp.storbinary("STOR test_upload.txt", io.BytesIO(b"test"))
                ftp.delete("test_upload.txt")

            try:
                FTP_Misconfigs._with_transfer_timeout(_upload_test)
                service_misconfigs.append(f"{user_type} has write access (test_upload.txt)")
            except (error_perm, OSError, all_errors):
                pass

            # Try to upload a fake PHP shell into web dirs
            for dir in WEB_DIRS:
                try:
                    ftp.cwd(dir)
                except (error_perm, OSError):
                    continue

                def _upload_shell():
                    fake_malicious_file = io.BytesIO(b"<?php echo 'hacked'; ?>")
                    filename = "test_shell.php"
                    ftp.storbinary(f"STOR {filename}", fake_malicious_file)
                    ftp.delete(filename)

                try:
                    FTP_Misconfigs._with_transfer_timeout(_upload_shell)
                    service_misconfigs.append(f"{user_type} uploaded PHP shell in {dir}")
                except (error_perm, OSError, all_errors):
                    # cannot upload here
                    continue

            # Check several permission actions in sensitive dirs
            for dir in SENSITIVE_DIRS:
                try:
                    ftp.cwd(dir)
                except (error_perm, OSError):
                    continue

                perms = []
                # write test
                def _write_test():
                    test_data = io.BytesIO(b"test")
                    ftp.storbinary("STOR write_test.txt", test_data)
                    ftp.delete("write_test.txt")

                try:
                    FTP_Misconfigs._with_transfer_timeout(_write_test)
                    perms.append("write")
                except (error_perm, OSError, all_errors):
                    pass

                # mkdir/rmdir test
                try:
                    ftp.mkd("testdir")
                    ftp.rmd("testdir")
                    perms.append("mkdir")
                    perms.append("delete")
                except (error_perm, OSError, all_errors):
                    pass

                if perms:
                    service_misconfigs.append(f"{user_type} has {perms} permissions in {dir}")

            # Check access to system dirs (list/pwd/cwd)
            for system_dir in SYSTEM_DIRS:
                try:
                    ftp.cwd(system_dir)
                    service_misconfigs.append(f"{user_type} can access system directory: {system_dir}")
                except (error_perm, OSError):
                    continue

            # For sensitive dirs, enumerate & try to download listed files and known sensitive filenames
            for dir in SENSITIVE_DIRS:
                try:
                    ftp.cwd(dir)
                except (error_perm, OSError):
                    continue

                service_misconfigs.append(f"{user_type} can access sensitive directory: {dir}")

                try:
                    listed_files = ftp.nlst()
                except (error_perm, OSError):
                    listed_files = []

                for file in listed_files:
                    def _retr_listed():
                        ftp.retrbinary(f"RETR {file}", lambda _: None)

                    try:
                        FTP_Misconfigs._with_transfer_timeout(_retr_listed)
                        service_misconfigs.append(f"{user_type} downloaded file from: {dir}{file}")
                    except (error_perm, OSError, all_errors):
                        continue

                for file in SENSITIVE_FILES:
                    def _retr_sensitive():
                        ftp.retrbinary(f"RETR {file}", lambda _: None)

                    try:
                        FTP_Misconfigs._with_transfer_timeout(_retr_sensitive)
                        service_misconfigs.append(f"{user_type} downloaded sensitive file: {dir}{file}")
                    except (error_perm, OSError, all_errors):
                        continue

        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def weak_authentication(service_misconfigs, ip, port, timeout):
        """
        This intentionally iterates COMMON_CREDENTIALS and weak passwords for a test user.
        Kept separate because it needs to try credentials individually.
        """
        consecutive_failures = 0

        # Try common credentials (each in a fresh connection)
        for username, password in COMMON_CREDENTIALS:
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                break

            ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
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
                FTP_Misconfigs._safe_ftp_close(ftp)
                sleep(DELAY)

        # Test a specific user (admin) for simple weak passwords
        consecutive_failures = 0
        test_user = "admin"
        weak_passwords = ["123456", "password", "admin", "ftp", "test", "root"]

        for pwd in weak_passwords:
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                break

            ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
            if not ftp:
                consecutive_failures += 1
                sleep(DELAY)
                continue

            try:
                ftp.login(user=test_user, passwd=pwd)
                service_misconfigs.append(f"Allowed weak password '{pwd}' for user '{test_user}' — password complexity missing")
                consecutive_failures = 0
                FTP_Misconfigs._safe_ftp_close(ftp)
                break
            except (error_perm, OSError):
                consecutive_failures += 1
            except all_errors:
                consecutive_failures += 1
                break
            finally:
                FTP_Misconfigs._safe_ftp_close(ftp)
                sleep(DELAY)

        return service_misconfigs

    @staticmethod
    def plaintext_authentication_missing_mfa(service_misconfigs, ip, port, timeout):
        """
        If we can connect (unencrypted) and login (even anonymously), it's plaintext auth.
        This method intentionally doesn't attempt credentials beyond a simple connect.
        """
        ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
        if ftp:
            FTP_Misconfigs._safe_ftp_close(ftp)
            service_misconfigs.append(f"FTP service on {ip}:{port} uses plaintext authentication (unencrypted login over FTP)")
            service_misconfigs.append(f"FTP service at {ip}:{port} does not enforce multi-factor authentication (MFA)")
        return service_misconfigs

    @staticmethod
    def no_account_lockout_policy(service_misconfigs, ip, port, timeout, max_attempts=10):
        """
        Try failed logins repeatedly to see if account lockout triggers.
        Kept using per-attempt fresh connections as original.
        """
        test_username = "nonexistent_user"
        test_password = "wrong_password"
        consecutive_failures = 0

        for attempt in range(max_attempts):
            ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
            if not ftp:
                break

            try:
                ftp.login(user=test_username, passwd=test_password)
            except (error_perm, OSError):
                consecutive_failures += 1
            except all_errors:
                break
            finally:
                FTP_Misconfigs._safe_ftp_close(ftp)
                sleep(DELAY)

        if consecutive_failures == max_attempts:
            service_misconfigs.append(f"No account lockout policy detected after {max_attempts} failed login attempts")

        return service_misconfigs

    @staticmethod
    def check_ftp_encryption(service_misconfigs, ip, port, timeout):
        """
        Check FTPS support (AUTH TLS / PROT P). If connection via FTP_TLS fails,
        fall back to plain FTP to mark lack of FTPS support.
        """
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
            except Exception:
                try:
                    ftps.close()
                except Exception:
                    pass

        except (OSError, TimeoutError, all_errors):
            ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
            if ftp:
                FTP_Misconfigs._safe_ftp_close(ftp)
                service_misconfigs.append("FTP server does NOT support FTPS (FTP over SSL/TLS) — no encryption available")
            else:
                service_misconfigs.append(f"Failed to connect to FTP server on port {port} — encryption check skipped")

        return service_misconfigs

    @staticmethod
    def unencrypted_file_transfer(service_misconfigs, ip, port, timeout):
        """
        If service uses the standard FTP port and allows login, it likely allows plaintext transfers.
        Note: Some servers run FTP on non-standard ports; we keep the original port==21 behaviour.
        """
        if port != 21:
            return service_misconfigs

        ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
        if ftp:
            try:
                # try an anonymous login; ftplib's login() with no args uses 'anonymous'
                try:
                    ftp.login()
                    service_misconfigs.append("FTP server on port 21 allows unencrypted file transfers (plaintext data and credentials).")
                except (error_perm, OSError):
                    pass
            finally:
                FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def check_ftp_directory_traversal(service_misconfigs, ip, port, timeout):
        """
        Try to login (anonymous or known creds) and attempt to escape root using '..' sequences.
        Uses _login_with_known_creds because original behavior tests anonymous then other creds.
        """
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
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
                            def _retr_listed():
                                ftp.retrbinary(f"RETR {file}", lambda _: None)

                            try:
                                FTP_Misconfigs._with_transfer_timeout(_retr_listed)
                                service_misconfigs.append(f"File access allowed to {user_type} outside FTP directory: {new_dir}{file}")
                            except (error_perm, OSError, all_errors):
                                continue
                        break
                except (error_perm, OSError):
                    continue
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def check_world_writable_dirs(service_misconfigs, ip, port, timeout):
        """
        Attempts to login (anonymous then other creds). Uses _test_directory_write for each dir.
        """
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        try:
            directories_to_check = SENSITIVE_DIRS + WEB_DIRS
            for d in directories_to_check:
                FTP_Misconfigs._test_directory_write(ftp, d, user_type, service_misconfigs)

                # If wrote successfully, also check for sensitive files readability in that dir
                try:
                    ftp.cwd(d)
                except (error_perm, OSError):
                    continue

                for file in SENSITIVE_FILES:
                    def _retr_sensitive():
                        ftp.retrbinary(f"RETR {file}", lambda _: None)

                    try:
                        FTP_Misconfigs._with_transfer_timeout(_retr_sensitive)
                        service_misconfigs.append(f"Sensitive file accessible via FTP: {d}/{file} by {user_type}")
                        service_misconfigs.append(f"Missing access control: {user_type} can read {d}{file}")
                    except (error_perm, OSError, all_errors):
                        continue
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def excessive_privilages(service_misconfigs, ip, port, timeout):
        """
        Tests whether FTP has access to OS system directories and whether it can write there.
        Uses _login_with_known_creds because original logic tries anonymous then others.
        """
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        try:
            for system_dir in SYSTEM_DIRS:
                try:
                    ftp.cwd(system_dir)
                    service_misconfigs.append(f"FTP service can access system directory: {system_dir} — excessive privileges")

                    # attempt to write a file
                    def _st_write():
                        filename = "privtest.txt"
                        data = io.BytesIO(b"test")
                        ftp.storbinary(f"STOR {filename}", data)
                        ftp.delete(filename)

                    try:
                        FTP_Misconfigs._with_transfer_timeout(_st_write)
                        service_misconfigs.append(f"FTP service can write in system directory: {system_dir} — critical misconfiguration")
                    except (error_perm, OSError, all_errors):
                        pass
                except (error_perm, OSError):
                    continue
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def check_unnecessary_ftp_features(service_misconfigs, ip, port, timeout):
        """
        Logs into (anonymous or known creds) and sends FEAT (if supported) to see
        dangerous/unused features enabled. Uses _login_with_known_creds pattern.
        """
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        try:
            try:
                features = []
                try:
                    reply = ftp.sendcmd("FEAT")
                    # sendcmd may return a string with newlines; splitlines to inspect lines
                    features = reply.splitlines() if isinstance(reply, str) else []
                except Exception:
                    features = []

                unnecessary = ["FXP", "SITE EXEC", "SITE CHMOD", "EPRT", "EPSV"]

                for feature in features:
                    for item in unnecessary:
                        if item in feature.upper():
                            service_misconfigs.append(f"Unnecessary FTP feature enabled: {item}")

            except Exception:
                pass
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def check_no_connection_limits(service_misconfigs, ip, port, timeout):
        """
        Attempt to open multiple concurrent connections from the same client.
        Closes them as the loop goes, but keeps a list to ensure cleanup in case of mid-loop exception.
        """
        connections = []
        try:
            for _ in range(MAX_CONCURRENT_CONNECTIONS):
                ftp = FTP()
                ftp.connect(ip, port, timeout=timeout)
                ftp.login('anonymous', 'anonymous@example.com')
                connections.append(ftp)

            service_misconfigs.append("No connection limits configured — server allows excessive concurrent connections from single client")
        except Exception:
            # if any connect or login fails we just stop - unable to assert unlimited connections
            pass
        finally:
            for ftp in connections:
                try:
                    ftp.quit()
                except Exception:
                    try:
                        ftp.close()
                    except Exception:
                        pass

        return service_misconfigs

    @staticmethod
    def check_missing_timeout(service_misconfigs, ip, port, timeout, sleep_duration=DEFAULT_SLEEP_DURATION):
        """
        Login then sleep for `sleep_duration`. If the session is still active afterwards,
        we consider there to be a missing idle timeout.
        """
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        try:
            start = time.time()
            sleep(sleep_duration)
            try:
                # If this raises, the session was dropped (good)
                ftp.pwd()
            except (error_temp, EOFError, error_reply, error_perm):
                return service_misconfigs

            service_misconfigs.append(f"Missing idle timeout configuration — session for {user_type} remained active after {sleep_duration} seconds of inactivity")
        except Exception:
            pass
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def check_insufficient_logging(service_misconfigs, ip, port, timeout):
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        marker = f"ftp_marker_{int(time.time())}"
        uploaded = False

        try:
            # upload marker
            def _upload_marker():
                ftp.storbinary(f"STOR {marker}.txt", io.BytesIO(b"marker"))
            try:
                FTP_Misconfigs._with_transfer_timeout(_upload_marker)
                uploaded = True
            except (error_perm, OSError, all_errors):
                uploaded = False

            # attempt a download to generate transfer log entry (if allowed)
            if uploaded:
                try:
                    def _retr_marker():
                        ftp.retrbinary(f"RETR {marker}.txt", lambda b: None)
                    FTP_Misconfigs._with_transfer_timeout(_retr_marker)
                except Exception:
                    pass

            # delete marker to clean up (ignore failures)
            try:
                ftp.delete(f"{marker}.txt")
            except Exception:
                pass

            found = False
            for logfile in GENERAL_LOGS:
                try:
                    buf = io.BytesIO()
                    def _retr_log():
                        ftp.retrbinary(f"RETR {logfile}", buf.write)
                    try:
                        FTP_Misconfigs._with_transfer_timeout(_retr_log)
                    except (error_perm, OSError, all_errors):
                        continue
                    content = buf.getvalue()
                    if not content:
                        continue
                    try:
                        if marker.encode() in content or b"STOR " in content or b"RETR " in content:
                            service_misconfigs.append(f"File transfer or marker entry found in accessible log: {logfile}")
                            found = True
                            break
                    except Exception:
                        continue
                except Exception:
                    continue

            if not found:
                service_misconfigs.append(
                    "No evidence of file transfer logging found in accessible log files — logging may be insufficient or logs are not accessible via FTP"
                )
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs
    
    @staticmethod
    def check_failed_login_logging(service_misconfigs, ip, port, timeout, attempts=3):
        marker_user = f"failtest_{int(time.time())}"
        test_password = "wrongpass"

        # Perform multiple failed login attempts
        for _ in range(attempts):
            ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
            if not ftp:
                return service_misconfigs
            try:
                ftp.login(user=marker_user, passwd=test_password)
            except (error_perm, OSError):
                pass
            finally:
                FTP_Misconfigs._safe_ftp_close(ftp)
                sleep(DELAY)  # avoid flooding

        # Try to find the marker in logs
        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        found = False
        for log_path in FAILED_LOGIN_LOGS:
            try:
                data = io.BytesIO()
                ftp.retrbinary(f"RETR {log_path}", data.write)
                log_contents = data.getvalue().decode(errors='ignore')
                if marker_user in log_contents or "authentication failure" in log_contents.lower():
                    found = True
                    break
            except (error_perm, OSError):
                continue

        if not found:
            service_misconfigs.append(
                "No evidence of failed login attempt logging — may hinder security incident investigations"
            )
        else:
            service_misconfigs.append(
                "Failed login attempts are being logged — ensure logs are secured"
            )

        FTP_Misconfigs._safe_ftp_close(ftp)
        return service_misconfigs

    @staticmethod
    def check_file_transfer_logging(service_misconfigs, ip, port, timeout):
        marker_filename = f"transfer_test_{int(time.time())}.txt"
        marker_content = b"file transfer logging test"

        ftp, user_type = FTP_Misconfigs._login_with_known_creds(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        try:
            # Upload a test file
            ftp.storbinary(f"STOR {marker_filename}", io.BytesIO(marker_content))

            # Download the file back
            data = io.BytesIO()
            ftp.retrbinary(f"RETR {marker_filename}", data.write)

            # Remove the file after test
            ftp.delete(marker_filename)
        except (error_perm, OSError):
            FTP_Misconfigs._safe_ftp_close(ftp)
            return service_misconfigs

        found = False
        for log_path in FILE_TRANSFER_LOGS:
            try:
                log_data = io.BytesIO()
                ftp.retrbinary(f"RETR {log_path}", log_data.write)
                if marker_filename in log_data.getvalue().decode(errors='ignore'):
                    found = True
                    break
            except (error_perm, OSError):
                continue

        if not found:
            service_misconfigs.append(
                "Missing file transfer logging — uploads/downloads are not recorded"
            )
        else:
            service_misconfigs.append(
                "File transfers are logged — ensure logs are secured"
            )

        FTP_Misconfigs._safe_ftp_close(ftp)
        return service_misconfigs

    @staticmethod
    def check_passive_mode_insecure_ports(ftp_host, ftp_port=21):
        service_misconfigs = []
        try:
            sock = socket.create_connection((ftp_host, ftp_port), timeout=10)
            sock.recv(1024)
            
            sock.sendall(b'USER anonymous\r\n')
            sock.recv(1024)
            sock.sendall(b'PASS anonymous@\r\n')
            sock.recv(1024)

            sock.sendall(b'PASV\r\n')
            pasv_response = sock.recv(1024).decode('utf-8', errors='ignore')

            import re
            match = re.search(r'\((\d+,\d+,\d+,\d+,\d+,\d+)\)', pasv_response)
            if match:
                parts = match.group(1).split(',')
                p1, p2 = int(parts[-2]), int(parts[-1])
                data_port = (p1 << 8) + p2

                if data_port < 1024 or data_port > 65535:
                    service_misconfigs.append(f"Passive mode uses insecure port {data_port} (PASV response: {pasv_response.strip()})")

            sock.close()
        except:
            pass

        return service_misconfigs
    
    @staticmethod
    def check_active_mode_insecure_behavior(ftp_host, ftp_port=21):
        service_misconfigs = []
        try:
            sock = socket.create_connection((ftp_host, ftp_port), timeout=10)
            sock.recv(1024)

            sock.sendall(b'USER anonymous\r\n')
            sock.recv(1024)
            sock.sendall(b'PASS anonymous@\r\n')
            sock.recv(1024)

            port_command = b'PORT 127,0,0,1,0,1\r\n'
            sock.sendall(port_command)
            response = sock.recv(1024).decode('utf-8', errors='ignore')

            if response.startswith('200') or response.startswith('220'):
                service_misconfigs.append("Active mode accepts potentially insecure PORT commands")

            sock.close()
        except:
            pass

        return service_misconfigs

    @staticmethod
    def check_outdated_ftp_version(service_misconfigs, ip, port, timeout):
        ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        try:
            banner = ftp.getwelcome().lower()
            for server_name, safe_version in LATEST_VERSIONS.items():
                if server_name in banner:
                    match = re.search(rf"{server_name}[^\d]*([\d\.]+)", banner)
                    if match:
                        detected_version = match.group(1)
                        if detected_version != safe_version:
                            service_misconfigs.append(
                                f"Outdated FTP server version detected: {server_name} {detected_version} (latest: {safe_version})"
                            )
                    break
        except (error_perm, OSError, all_errors):
            pass
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

    @staticmethod
    def check_eol_ftp_version(service_misconfigs, ip, port, timeout):
        """Detect if FTP server is an end-of-life version based on banner"""
        ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        try:
            banner = ftp.getwelcome().lower()
            for server_name, last_version in EOL_FTP_VERSIONS.items():
                if server_name in banner:
                    if last_version:
                        service_misconfigs.append(
                            f"FTP server {server_name} detected — last known version {last_version} (EOL)"
                        )
                    else:
                        service_misconfigs.append(
                            f"FTP server {server_name} detected — project discontinued (EOL)"
                        )
                    break
        except Exception:
            pass
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs
    
    @staticmethod
    def check_default_configurations(service_misconfigs, ip, port, timeout):
        """Detect FTP servers running with default banners or default credentials"""
        ftp = FTP_Misconfigs._safe_ftp_connect(ip, port, timeout)
        if not ftp:
            return service_misconfigs

        logged_in = False
        user_type = None

        try:
            # === Banner Check ===
            banner = ftp.getwelcome().lower()
            for default_banner in DEFAULT_FTP_BANNERS:
                if default_banner.lower() in banner:
                    service_misconfigs.append(
                        f"Default FTP banner detected: '{banner.strip()}' — possible default configuration"
                    )
                    break

            # === Credential Check ===
            try:
                ftp.login(user='anonymous', passwd='anonymous@example.com')
                service_misconfigs.append("Anonymous authentication allowed — default config not changed")
                logged_in = True
                user_type = 'anonymous'
            except (error_perm, OSError):
                for username, password in COMMON_CREDENTIALS + DEFAULT_CREDENTIALS:
                    try:
                        ftp.login(user=username, passwd=password)
                        service_misconfigs.append(
                            f"Default credentials accepted: {username}:{password}"
                        )
                        logged_in = True
                        user_type = f"{username}:{password}"
                        break
                    except (error_perm, OSError):
                        continue

        except Exception:
            pass
        finally:
            FTP_Misconfigs._safe_ftp_close(ftp)

        return service_misconfigs

import paramiko

class SSH_Misconfigs:

    @staticmethod
    def SSH_misconfigs(ip, port, timeout, misconfigs):
        """
        Populate misconfigs[service][category] for SSH service.
        """
        service = "ssh"
        if service not in misconfigs:
            misconfigs[service] = {}

        def ensure_category(cat):
            if cat not in misconfigs[service]:
                misconfigs[service][cat] = []
            return misconfigs[service][cat]

        auth_cat = ensure_category("Authentication and Access Control")

        # Try each credential only once, reuse session for checks
        credential_attempts = [
            ("root", ""),  # empty password root
            ("admin", ""),  # empty password admin
            ("root", "root"),
            ("root", "admin"),
            ("root", "123456"),
            ("root", "password"),
            ("root", "toor"),
        ]

        for username, password in credential_attempts:
            ssh = SSH_Misconfigs._safe_ssh_connect(ip, port, username, password, timeout)
            if ssh:
                # Pass session to checks
                SSH_Misconfigs.check_permit_root_login(auth_cat, ssh, username, password)
                SSH_Misconfigs.check_permit_empty_passwords(auth_cat, ssh, username, password)
                SSH_Misconfigs.check_password_auth_root(auth_cat, ssh, username, password)
                SSH_Misconfigs.check_password_auth_enabled(auth_cat, ssh, username, password)

                SSH_Misconfigs._safe_ssh_close(ssh)
                break  # stop after first successful login

        return misconfigs

    # ------------------ Internal Helpers ------------------

    @staticmethod
    def _safe_ssh_connect(ip, port, username, password, timeout):
        """Attempt SSH connection with given creds, return SSHClient or None."""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )
            return ssh
        except Exception:
            return None

    @staticmethod
    def _safe_ssh_close(ssh_client):
        """Close SSH connection if open."""
        try:
            if ssh_client:
                ssh_client.close()
        except Exception:
            pass

    # ------------------ Checks ------------------

    @staticmethod
    def check_permit_root_login(service_misconfigs, ssh_session, username, password):
        if username == "root" and password != "":
            service_misconfigs.append("PermitRootLogin enabled: SSH server allows direct root login with password authentication.")

    @staticmethod
    def check_permit_empty_passwords(service_misconfigs, ssh_session, username, password):
        if password == "":
            service_misconfigs.append(f"PermitEmptyPasswords enabled: SSH server allows login for user '{username}' with no password.")

    @staticmethod
    def check_password_auth_root(service_misconfigs, ssh_session, username, password):
        if username == "root" and password != "":
            service_misconfigs.append("Password authentication enabled for root user.")
            service_misconfigs.append("No key-based authentication required for root: server allows password login for root.")
            
    @staticmethod
    def check_password_auth_enabled(service_misconfigs, username, password):
        if password != "":
            service_misconfigs.append(f"PasswordAuthentication enabled: SSH server allows password login for user '{username}' instead of requiring key-based authentication.")
            
    @staticmethod
    def check_weak_password(service_misconfigs, username, password):
        if password in WEAK_PASSWORDS:
            service_misconfigs.append(
                f"Weak password vulnerability: account '{username}' is protected with a commonly used or easily guessable password '{password or '<empty>'}'."
            )