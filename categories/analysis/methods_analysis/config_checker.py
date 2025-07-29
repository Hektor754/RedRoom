from categories.recon.methods_recon.digital_fingerprinting.find_ports import PortScan
from ftplib import FTP,error_perm
import argparse
import getpass

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

class Configuration_checker:

    @staticmethod
    def get_credentials():
        parser = argparse.ArgumentParser(description='FTP misconfiguration scanner')
        parser.add_argument('-u', '--username', help='FTP username')
        parser.add_argument('-p', '--password', help='FTP password')
        args = parser.parse_args()

        username = args.username
        password = args.password

        if not username:
            username = input("Enter FTP username (leave blank for anonymous): ").strip()
            if not username:
                username = 'anonymous'

        if not password and username.lower() != 'anonymous':
            password = getpass.getpass(f"Enter password for {username}: ")

        return username, password
    
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

        # === Anonymous login checks ===
        ftp = FTP()
        try:
            ftp.connect(host=ip, port=port, timeout=timeout)
            ftp.login(user='anonymous', passwd='anonymous@example.com')
            service_misconfigs.append("Anonymous authentication allowed with username 'anonymous'")
            ftp.quit()
        except error_perm:
            pass

        ftp = FTP()
        try:
            ftp.connect(host=ip, port=port, timeout=timeout)
            ftp.login(user='ftp', passwd='anonymous@example.com')
            service_misconfigs.append("Anonymous authentication allowed with username 'ftp'")
            ftp.quit()
        except error_perm:
            pass

        # === Authenticated access checks ===
        usr, passwd = Configuration_checker.get_credentials()

        try:
            ftp = FTP()
            ftp.connect(host=ip, port=port, timeout=timeout)
            ftp.login(usr, passwd)

            for dir in SENSITIVE_DIRS:
                try:
                    ftp.cwd(dir)
                    service_misconfigs.append(f"Access granted to sensitive directory: {dir}")

                    try:
                        listed_files = ftp.nlst()
                    except:
                        listed_files = []

                    for file in listed_files:
                        try:
                            ftp.retrbinary(f"RETR {file}", lambda _: None)
                            service_misconfigs.append(f"Download allowed for listed file: {dir}{file}")
                        except error_perm:
                            continue

                    for file in SENSITIVE_FILES:
                        try:
                            ftp.retrbinary(f"RETR {file}", lambda _: None)
                            service_misconfigs.append(f"Download allowed for sensitive file: {dir}{file}")
                        except error_perm:
                            continue

                except error_perm:
                    continue

            ftp.quit()
        except Exception as e:
            print(f"[!] Failed to log in or scan FTP with provided credentials: {e}")

            







