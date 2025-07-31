from categories.recon.methods_recon.digital_fingerprinting.find_ports import PortScan
from ftplib import FTP,error_perm, all_errors
import argparse
import getpass
import io

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
        
        return misconfigs

    @staticmethod
    def anonymous_auth_msconf(service_misconfigs, ip, port, timeout):
        ftp = FTP()
        try:
            ftp.connect(host=ip, port=port, timeout=timeout)
            ftp.login(user='anonymous', passwd='anonymous@example.com')
            service_misconfigs.append("Anonymous authentication allowed with username 'anonymous'")
            try:
                ftp.storbinary("STOR test_upload.txt", io.BytesIO(b"test"))
                service_misconfigs.append("Anonymous write access enabled")
                ftp.delete("test_upload.txt")
            except error_perm:
                pass
            try:
                for dir in WEB_DIRS:
                    ftp.cwd(dir)
                    fake_malicious_file = io.BytesIO(b"<?php echo 'hacked'; ?>")
                    filename = "test_shell.php"
                    ftp.storbinary(f"STOR {filename}", fake_malicious_file)
                    service_misconfigs.append(f"Anonymous user able to upload PHP file in {dir} — high risk of remote code execution")
                    ftp.delete(filename)
            except error_perm:
                pass

            try:
                for dir in SENSITIVE_DIRS:
                    perms = []
                    ftp.cwd(dir)
                    data = io.BytesIO(b"test")
                    ftp.storbinary("STOR write_test.txt", data)
                    perms.append("write")
                    ftp.delete("write_test.txt")
                    perms.append("delete")
                    ftp.mkd("testdir")
                    perms.append("mkdir")
                    ftp.rmd("testdir")
                    if len(perms) != 0:
                        service_misconfigs.append(f"Anonymous user has {perms[0:len(perms)]} permissions in {dir} — overly broad access")
                for system_dir in SYSTEM_DIRS:
                    try:
                        ftp.cwd(system_dir)
                        service_misconfigs.append(f"Anonymous user can access system directory: {system_dir}")
                    except error_perm:
                        continue
            except error_perm:
                pass
            for dir in SENSITIVE_DIRS:
                try:
                    ftp.cwd(dir)
                    service_misconfigs.append(f"Access granted to anonymous user on sensitive directory: {dir}")

                    try:
                        listed_files = ftp.nlst()
                    except:
                        listed_files = []

                    for file in listed_files:
                        try:
                            ftp.retrbinary(f"RETR {file}", lambda _: None)
                            service_misconfigs.append(f"Download allowed to anonymous user for listed file: {dir}{file}")
                        except error_perm:
                            continue

                    for file in SENSITIVE_FILES:
                        try:
                            ftp.retrbinary(f"RETR {file}", lambda _: None)
                            service_misconfigs.append(f"Download allowed to anonymous user for sensitive file: {dir}{file}")
                        except error_perm:
                            continue
                except error_perm:
                    pass
            ftp.quit()
        except error_perm:
            pass     
        return service_misconfigs

    @staticmethod
    def weak_authentication(service_misconfigs, ip, port, timeout):
        for username, password in COMMON_CREDENTIALS:
            try:
                ftp = FTP()
                ftp.connect(ip, port, timeout=timeout)
                ftp.login(user=username, passwd=password)
                service_misconfigs.append(f"Allowed Login with weak credentials: {username}, {password}")
                ftp.quit()
            except error_perm:
                continue
            except all_errors as e:
                continue
        return service_misconfigs

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