import re
from dataclasses import dataclass

@dataclass
class SecurityIssue:
    """Bitta xavfsizlik muammosini ifodalaydi"""
    vulnerability_type: str   # masalan: "sql_injection"
    severity: str             # "HIGH", "MEDIUM", "LOW"
    line_number: int          # qaysi qatorda topildi
    matched_code: str         # topilgan kod parchasi
    description: str          # muammo tavsifi
    fix_suggestion: str       # qanday tuzatish kerak

# Xavfsizlik muammolarini aniqlash uchun regex patternlar
# Bu patternlar OWASP Top 10 asosida tuzilgan
SECURITY_PATTERNS = {
    "sql_injection": {
        "patterns": [
            r'query\s*[+=]\s*["\'].*?\+',           # "SELECT * FROM " + user_input
            r'execute\s*\(\s*["\'].*?%s',            # execute("...%s", data)
            r'cursor\.execute\s*\(.*?\+',            # cursor.execute("..." + var)
            r'f["\'].*?SELECT.*?\{',                 # f"SELECT * FROM {table}"
        ],
        "severity": "HIGH",
        "description": "SQL Injection zaiflik topildi. Foydalanuvchi kiritgan ma'lumot to'g'ridan-to'g'ri SQL ga kiritilmoqda.",
        "fix": "Parameterized queries yoki ORM ishlatish kerak. Masalan: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    },
    "hardcoded_secret": {
        "patterns": [
            r'password\s*=\s*["\'][^"\']{4,}["\']',  # password = "abc123"
            r'api_key\s*=\s*["\'][^"\']{8,}["\']',   # api_key = "sk-xxx"
            r'secret\s*=\s*["\'][^"\']{4,}["\']',    # secret = "mysecret"
            r'token\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']',  # token = "ghp_xxx"
        ],
        "severity": "HIGH",
        "description": "Kod ichida hardcoded maxfiy ma'lumot topildi.",
        "fix": "Maxfiy ma'lumotlarni environment variables (.env fayl) orqali oling: os.getenv('SECRET_KEY')"
    },
    "xss_vulnerability": {
        "patterns": [
            r'innerHTML\s*=\s*(?![\'"]\s*[\'"])',  # el.innerHTML = userInput
            r'document\.write\s*\(',                # document.write(data)
            r'eval\s*\(',                           # eval(userCode)
            r'dangerouslySetInnerHTML',             # React XSS
        ],
        "severity": "HIGH",
        "description": "Cross-Site Scripting (XSS) zaiflik topildi.",
        "fix": "innerHTML o'rniga textContent ishlating, yoki DOMPurify kutubxonasi bilan tozalang."
    },
    "weak_crypto": {
        "patterns": [
            r'md5\s*\(',        # md5() - eskirgan
            r'sha1\s*\(',       # sha1() - zaif
            r'DES\s*\(',        # DES encryption - zaif
            r'hashlib\.md5',    # Python md5
        ],
        "severity": "MEDIUM",
        "description": "Zaif kriptografiya algoritmi ishlatilmoqda.",
        "fix": "MD5/SHA1 o'rniga SHA-256 yoki bcrypt ishlating. Parollar uchun bcrypt/argon2 tavsiya etiladi."
    },
    "insecure_random": {
        "patterns": [
            r'Math\.random\s*\(',         # JavaScript
            r'random\.random\s*\(',       # Python - kriptografik emas
            r'rand\s*\(',                 # PHP
        ],
        "severity": "MEDIUM",
        "description": "Xavfsizlik uchun mos bo'lmagan random funksiya ishlatilmoqda.",
        "fix": "Kriptografik random uchun: Python - secrets.token_hex(), JS - crypto.getRandomValues()"
    },
    "path_traversal": {
        "patterns": [
            r'open\s*\(.*?\+',           # open("path/" + user_input)
            r'readFile\s*\(.*?\+',       # Node.js readFile
            r'\.\./|\.\.\\',             # ../../../etc/passwd
        ],
        "severity": "HIGH",
        "description": "Path Traversal zaiflik - foydalanuvchi fayl yo'lini boshqarishi mumkin.",
        "fix": "os.path.realpath() va os.path.abspath() bilan yo'lni tekshiring."
    }
}


def scan_code_for_vulnerabilities(code: str) -> list[SecurityIssue]:
    """
    Berilgan kodni xavfsizlik muammolari uchun tekshiradi.
    
    Qanday ishlaydi:
    1. Har bir vulnerability type uchun patternlarni tekshiradi
    2. Topilgan joylarda qator raqamini hisoblab chiqadi
    3. SecurityIssue ob'ektlari ro'yxatini qaytaradi
    """
    issues = []
    lines = code.split('\n')
    
    for vuln_type, vuln_info in SECURITY_PATTERNS.items():
        for pattern in vuln_info["patterns"]:
            # re.IGNORECASE — katta/kichik harfga e'tibor bermaslik
            for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                # Topilgan pozitsiyadan qator raqamini hisoblaymiz
                line_number = code[:match.start()].count('\n') + 1
                
                # Topilgan kod parchasi (maksimal 100 belgi)
                matched_text = match.group(0)[:100]
                
                issue = SecurityIssue(
                    vulnerability_type=vuln_type,
                    severity=vuln_info["severity"],
                    line_number=line_number,
                    matched_code=matched_text,
                    description=vuln_info["description"],
                    fix_suggestion=vuln_info["fix"]
                )
                issues.append(issue)
    
    return issues


def format_security_report(issues: list[SecurityIssue]) -> str:
    """
    Security issues ro'yxatini GitHub comment uchun chiroyli formatga o'tkazadi.
    Markdown formatida yoziladi.
    """
    if not issues:
        return "✅ **Security scan:** Hech qanday xavfsizlik muammosi topilmadi."
    
    # Severity bo'yicha ajratamiz
    high = [i for i in issues if i.severity == "HIGH"]
    medium = [i for i in issues if i.severity == "MEDIUM"]
    low = [i for i in issues if i.severity == "LOW"]
    
    report = f"## 🔐 Security Scan Natijasi\n\n"
    report += f"**Jami muammolar:** {len(issues)} ta "
    report += f"(🔴 {len(high)} HIGH, 🟡 {len(medium)} MEDIUM, 🟢 {len(low)} LOW)\n\n"
    
    for issue in sorted(issues, key=lambda x: x.severity):
        emoji = "🔴" if issue.severity == "HIGH" else "🟡" if issue.severity == "MEDIUM" else "🟢"
        report += f"### {emoji} {issue.vulnerability_type.replace('_', ' ').title()}\n"
        report += f"- **Qator:** {issue.line_number}\n"
        report += f"- **Topilgan kod:** `{issue.matched_code}`\n"
        report += f"- **Muammo:** {issue.description}\n"
        report += f"- **Tuzatish:** {issue.fix_suggestion}\n\n"
    
    return report