# SSL Cert Builder - A Retro Desktop Tool for Managing SSL Certificates on Windows Server

**I got tired of the manual, error-prone process of installing SSL certificates on Windows Server with IIS, so I built a desktop utility to handle the entire workflow from start to finish.**

---

## The Problem

If you've ever had to install an SSL certificate on a Windows Server running IIS, you know the pain:

- Generate a CSR somewhere, keep track of the private key
- Submit the CSR to your provider, wait for the cert
- Receive a zip with cryptic files (.crt, .ca-bundle, .p7b) and figure out which is which
- Somehow combine everything into a PFX and import it into the Windows certificate store
- Bind it to the right IIS site on the right port
- Pray nothing went wrong

Miss one step or lose the private key? Start over.

## The Solution

**SSL Cert Builder** is a Python + Tkinter desktop app that handles the entire SSL certificate lifecycle in one place:

### 1. Generate CSR
Enter your domain (supports wildcards like `*.example.com`), organization details, and key size. The app generates a private key and CSR, saves both to disk, and displays the CSR ready to copy to your clipboard and paste into your SSL provider's portal.

### 2. Import Certificates
When your provider sends back the cert files, just point the app at the folder. It **auto-detects** `.crt`, `.key`, `.ca-bundle`, `.pem`, and `.txt` files - no need to select each one individually. It even handles RTF-formatted files (looking at you, TextEdit on Mac).

The app automatically:
- Identifies the server certificate vs. intermediate CAs vs. root CA
- Finds and pairs the matching private key
- Validates the certificate chain

### 3. Inspect Everything
The Certificate Details view breaks down every cert in the chain:
- Common Name, SANs, Subject, Issuer
- Serial number and SHA-1 thumbprint
- Validity dates with expiry warnings (30/90 day alerts)
- Chain length and private key status

### 4. Export Components
Need the cert in different formats? One click exports:
- `server.crt` - Server certificate
- `server.key` - Private key
- `ca-bundle.crt` - Intermediate + root chain
- `fullchain.pem` - Complete chain
- `certificate.pfx` - PKCS#12 archive (auto-generated)

### 5. Install to IIS
The Install page checks all prerequisites (admin rights, IIS module availability), lists your IIS sites, and lets you configure the binding (IP, port, SNI hostname). One click:
1. Builds a PFX from your cert + key + chain
2. Imports it into the Windows certificate store
3. Creates/updates the HTTPS binding on your chosen IIS site
4. Optionally restarts the site

---

## Tech Stack

- **Python 3.11+** with Tkinter (ships with Python, no extra GUI framework needed)
- **cryptography** library for cert parsing, CSR generation, and PFX creation
- **Pillow** for the optional retro background image
- **PowerShell** under the hood for Windows cert store and IIS management
- Runs as a single app - no server, no browser, no Electron

## Architecture

```
cert_builder.py   - Main GUI (sidebar nav, 4 pages, theming)
cert_utils.py     - Certificate parsing, CSR generation, PFX building
iis_manager.py    - Windows cert store + IIS PowerShell integration
requirements.txt  - cryptography, Pillow
background.png    - Optional retro synthwave background
```

## The Theme

Because enterprise tools don't have to be boring - it's rocking a **retro 80s/90s Taco Bell** color scheme with hot pink accents, teal success indicators, golden yellow warnings, and a synthwave banner on every page. Dark purple everything. Radical Edition.

---

## Quick Start

```powershell
# On your Windows Server (run as Administrator)
pip install cryptography Pillow
python cert_builder.py
```

## The Workflow

```
Generate CSR  -->  Submit to Provider  -->  Import from Folder  -->  Install to IIS
     |                                            |                        |
  Saves .key          Provider sends           Auto-detects            One-click
  and .csr            .crt + .ca-bundle        all cert files         IIS binding
```

---

Built with Python. Themed with nostalgia. Ships SSL certs without the headache.
