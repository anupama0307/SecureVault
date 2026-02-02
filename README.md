# 🔐 SecureVault

A comprehensive demonstration of cybersecurity concepts including encryption, digital signatures, multi-factor authentication, and role-based access control for academic password and document management.

---

## 📸 Screenshots

### 1. Secure Registration
*Enforces strong password policy (uppercase, lowercase, special chars) with role selection (Student/Faculty)*

### 2. Multi-Factor Authentication
*OTP is sent to the secure server console (simulating SMS/Email)*

### 3. Password Recovery Flow
*Secure identity verification before password reset*

### 4. Password Reset
*New password must also meet strict security requirements*

### 5. Student Password Vault
*Securely store, manage, and autogenerate passwords for personal use*

### 6. Add New Password
*"I have a password" / "Autogenerate" toggle with secure storage*

### 7. Faculty Upload Dashboard
*Upload quiz passwords, protected PDFs, and question papers*

### 8. Document Integrity Verification
*Digital signatures ensure unauthorized modifications are detected immediately*

### 9. Admin Dashboard
*Full control over user management and security monitoring*

### 10. User Management
*Admin view of all registered students, faculty, and their roles*

### 12. Biometric Authentication (WebAuthn)
*Passwordless login using FaceID, TouchID, or Windows Hello*

---

## Architecture

```
SecureVault/
├── backend/                      # Flask API Server
│   ├── app.py                   # Entry point
│   ├── config.py                # Keys & settings
│   ├── models.py                # Database operations
│   ├── routes/
│   │   ├── auth.py              # Authentication endpoints
│   │   ├── passwords.py         # Student password vault
│   │   ├── resources.py         # Faculty document management
│   │   └── admin.py             # Admin operations
│   └── utils/
│       ├── access_control.py    # RBAC & JWT
│       ├── crypto.py            # Encryption & signing
│       ├── otp.py               # MFA utilities
│       └── webauthn_utils.py    # Passkey utilities
│
└── frontend/                     # Next.js Web App
    └── app/
        ├── page.tsx             # Login page
        ├── signup/              # Registration
        ├── profile/             # User profile & Passkeys
        ├── reset-password/      # Password reset
        ├── dashboard/           # Role-based router
        ├── student/
        │   ├── vault/           # Password vault
        │   ├── add-password/    # Add new password
        │   ├── edit-password/   # Edit password
        │   └── resources/       # View shared resources
        ├── faculty/
        │   ├── dashboard/       # Faculty console
        │   ├── upload-quiz/     # Upload quiz password
        │   ├── upload-pdf/      # Upload protected PDF
        │   └── my-uploads/      # Manage uploads
        └── admin/
            ├── dashboard/       # Admin console
            ├── users/           # User management
            └── audit-logs/      # Security logs
```

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend Setup
1. Navigate to backend:
   ```bash
   cd backend
   ```
2. Create virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. **Configure Environment (Optional):**
   - The app runs fine with defaults!
   - For email OTPs, create a `.env` file (see `.env.example` if available) with `MAIL_USERNAME` and `MAIL_PASSWORD`.
   
5. **Run Server:**
   ```bash
   python app.py
   ```
   > **Note:** On the first run, the application will **automatically**:
   > - 🔑 Generate new RSA & AES encryption keys (in `backend/keys/`)
   > - 🗄️ Create the SQLite database (`secure_storage.db`)
   > - 👤 Create demo accounts (`admin`, `faculty1`, `student1`)

### Frontend Setup

### Frontend Setup
1. Navigate to frontend:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run Development Server:
   ```bash
   npm run dev
   ```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Demo Accounts

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| `admin` | `admin123` | Admin | View users, audit logs, full access |
| `faculty1` | `faculty123` | Faculty | Upload PDFs, quiz passwords, QPs |
| `student1` | `student123` | Student | Store passwords, view resources |

---

## Access Control Matrix

| Action / Role | Student | Faculty | Admin |
|---------------|---------|---------|-------|
| Store Personal Passwords | ✅ | ❌ | ❌ |
| View/Edit Own Passwords | ✅ | ❌ | ❌ |
| Register Passkeys | ✅ | ✅ | ✅ |
| Upload Quiz Passwords | ❌ | ✅ | ❌ |
| Upload Protected PDFs | ❌ | ✅ | ❌ |
| Upload Question Papers | ❌ | ✅ | ❌ |
| View Shared Resources | ✅ (Read-Only) | ✅ | ✅ |
| View All Users | ❌ | ❌ | ✅ |
| View Audit Logs | ❌ | ❌ | ✅ |

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create new account (Student/Faculty) |
| POST | `/auth/login` | Password verification → OTP sent |
| POST | `/auth/verify-otp` | Complete MFA → JWT issued |
| POST | `/auth/webauthn/register/*` | Passkey registration |
| POST | `/auth/webauthn/login/*` | Passwordless login |
| POST | `/auth/forgot-password` | Request password reset OTP |
| POST | `/auth/reset-password` | Reset password with OTP |
| GET | `/auth/me` | Get current user info |

### Student Password Vault
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/passwords` | List all saved passwords |
| POST | `/passwords` | Add new password |
| GET | `/passwords/<id>` | Get single password |
| PUT | `/passwords/<id>` | Update password |
| DELETE | `/passwords/<id>` | Delete password |
| POST | `/passwords/generate` | Autogenerate secure password |

### Faculty Resources
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/resources/quiz-password` | Upload quiz access password |
| POST | `/resources/pdf` | Upload protected PDF |
| POST | `/resources/question-paper` | Upload question paper |
| GET | `/resources/my-uploads` | Get own uploads |
| DELETE | `/resources/<id>` | Delete own upload |
| GET | `/resources/shared` | View all shared resources |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | List all users |
| GET | `/audit-logs` | Get security event logs |
| GET | `/access-control` | View ACM documentation |

---

## Security Concepts Demonstrated

### 1. Encoding vs Encryption
- **Base64**: Format conversion (NOT security) - anyone can decode
- **AES-256**: Symmetric encryption - data unreadable without key

### 2. Hashing vs Encryption
- **Hashing (PBKDF2)**: One-way, used for passwords (100,000 iterations with salt)
- **Encryption (AES)**: Two-way, used for stored passwords & documents

### 3. Digital Signatures
- **RSA-PSS**: Proves authenticity + integrity
- Any tampering invalidates the signature
- Used for uploaded documents to verify they haven't been modified

---

## Encrypted Token Format

```
Base64( IV[16 bytes] + Signature[256 bytes] + Ciphertext )
```

1. **IV**: Random initialization vector for AES
2. **Signature**: RSA-PSS signature of ciphertext
3. **Ciphertext**: AES-256-CBC encrypted payload

---

## Important Notes

- **RSA keys** are saved to `/backend/keys/` and persist across restarts
- **OTPs** are displayed in server console (demo mode - simulating SMS/Email)
- **Faculty uploads** plain files → system automatically encrypts & signs them
- **Students** can only decrypt and read resources, not modify or delete them
- All passwords in vault are encrypted with AES-256 before storage

---

## Testing the Security Features

### Password Vault (Student)
1. Login as `student1` / `student123`
2. Add a new password (manual or autogenerate)
3. View saved passwords with search
4. Test Edit, Delete (confirmation popup), Copy buttons

### Document Upload (Faculty)
1. Login as `faculty1` / `faculty123`
2. Upload a quiz password or PDF
3. System encrypts and signs automatically
4. View upload in "My Uploads"

### QP Tamper Detection
1. Upload a question paper (as Faculty)
2. Login as Student and go to Shared Resources
3. Click "Verify Integrity" on a question paper
4. Click **"Validate"** - should show ✅ Valid
5. Click **"Tamper"** button to modify the token
6. Click **"Validate"** again - should show ❌ Invalid (tampering detected)

### Admin Monitoring
1. Login as `admin` / `admin123`
2. View all registered users
3. View comprehensive audit logs

---

## Attack Countermeasures

| Attack | Countermeasure |
|--------|----------------|
| Brute Force | PBKDF2 with 100k iterations |
| Rainbow Table | Random salt per password |
| SQL Injection | Parameterized queries |
| Token Tampering | RSA digital signature |
| Session Hijacking | JWT with 24h expiry |
| MFA Bypass | OTP with 5-min expiry |
| Privilege Escalation | Role-based access control |

---

## Token API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/resources/token/<id>` | Get encrypted token for verification |
| POST | `/resources/verify-token/<id>` | Verify token (detects tampering) |
| GET | `/resources/verify/<id>` | Quick integrity check |


---

## Tech Stack

**Backend:**
- Python 3.10+
- Flask
- SQLite
- cryptography library
- PyJWT

**Frontend:**
- Next.js 14
- React
- TypeScript
- TailwindCSS

**Security:**
- JWT (HS256)
- PBKDF2-SHA256 (100k iterations)
- AES-256-CBC
- RSA-2048-PSS
- FIDO2 / WebAuthn (Passkeys)
- Base64 encoding

---

## NIST SP 800-63-2 Compliance

The registration and login processes follow the NIST E-Authentication Architecture Model:
- **Strong password policy** enforcement
- **Multi-factor authentication** (password + OTP)
- **Biometric Authentication** (FIDO2/WebAuthn)
- **Rate limiting** on failed login attempts
- **Secure session management** with JWT tokens

---



## License

This project is for educational purposes - 23CSE313 Foundations of Cyber Security Lab Evaluation.

---

**Built with 🔒 Security First**
