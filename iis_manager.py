"""
iis_manager.py - Windows Certificate Store and IIS management.

Uses PowerShell and certutil to:
- Import PFX into the Windows certificate store
- List IIS websites
- Bind SSL certificates to IIS sites
"""

import subprocess
import tempfile
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IISSite:
    """Represents an IIS website."""
    name: str
    id: int
    state: str
    bindings: str


def _run_powershell(script: str) -> tuple[str, str, int]:
    """
    Execute a PowerShell command and return (stdout, stderr, returncode).
    """
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def _run_certutil(args: list[str]) -> tuple[str, str, int]:
    """Execute certutil.exe with given arguments."""
    result = subprocess.run(
        ["certutil.exe"] + args,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def check_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        stdout, _, rc = _run_powershell(
            "([Security.Principal.WindowsPrincipal] "
            "[Security.Principal.WindowsIdentity]::GetCurrent()"
            ").IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        )
        return stdout.strip().lower() == "true"
    except Exception:
        return False


def check_iis_installed() -> bool:
    """Check if IIS is installed and the WebAdministration module is available."""
    try:
        stdout, _, rc = _run_powershell(
            "if (Get-Module -ListAvailable -Name WebAdministration) "
            "{ 'yes' } else { 'no' }"
        )
        return "yes" in stdout.lower()
    except Exception:
        return False


def import_pfx_to_store(
    pfx_path: str,
    password: Optional[str] = None,
    store_name: str = "My",
    store_location: str = "LocalMachine",
) -> tuple[bool, str]:
    """
    Import a PFX file into the Windows certificate store.

    Args:
        pfx_path: Path to the PFX file.
        password: Password for the PFX file (None for no password).
        store_name: Certificate store name (default: "My" = Personal).
        store_location: Store location (default: "LocalMachine").

    Returns:
        (success: bool, message: str)
    """
    # Escape the path for PowerShell
    pfx_path_escaped = pfx_path.replace("'", "''")

    if password:
        pwd_escaped = password.replace("'", "''")
        pwd_line = f"$pwd = ConvertTo-SecureString -String '{pwd_escaped}' -Force -AsPlainText"
    else:
        pwd_line = "$pwd = New-Object System.Security.SecureString"

    script = f"""
{pwd_line}
$pfx = Import-PfxCertificate -FilePath '{pfx_path_escaped}' `
    -CertStoreLocation 'Cert:\\{store_location}\\{store_name}' `
    -Password $pwd `
    -Exportable
$pfx.Thumbprint
"""

    stdout, stderr, rc = _run_powershell(script)

    if rc != 0:
        return False, f"Failed to import PFX: {stderr}"

    thumbprint = stdout.strip().split("\n")[-1].strip()
    if thumbprint and len(thumbprint) == 40:
        return True, thumbprint
    else:
        return True, f"Imported (output: {stdout})"


def get_iis_sites() -> tuple[list[IISSite], str]:
    """
    Get a list of all IIS websites.

    Returns:
        (sites: list[IISSite], error: str)
    """
    script = """
Import-Module WebAdministration -ErrorAction Stop
Get-Website | ForEach-Object {
    $bindings = ($_.Bindings.Collection | ForEach-Object { $_.bindingInformation }) -join '; '
    "$($_.Name)|$($_.ID)|$($_.State)|$bindings"
}
"""

    stdout, stderr, rc = _run_powershell(script)

    if rc != 0:
        return [], f"Failed to query IIS sites: {stderr}"

    sites = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 3)
        if len(parts) >= 3:
            try:
                site = IISSite(
                    name=parts[0],
                    id=int(parts[1]),
                    state=parts[2],
                    bindings=parts[3] if len(parts) > 3 else "",
                )
                sites.append(site)
            except (ValueError, IndexError):
                continue

    return sites, ""


def bind_cert_to_site(
    site_name: str,
    thumbprint: str,
    ip: str = "*",
    port: int = 443,
    hostname: str = "",
    store_name: str = "My",
) -> tuple[bool, str]:
    """
    Bind an SSL certificate to an IIS site.

    This removes any existing HTTPS binding on the same IP:port:hostname
    and creates a new one with the specified certificate.

    Args:
        site_name: IIS site name.
        thumbprint: Certificate thumbprint (from the cert store).
        ip: IP address to bind to (* for all).
        port: HTTPS port (default 443).
        hostname: SNI hostname (empty for no SNI).
        store_name: Certificate store name.

    Returns:
        (success: bool, message: str)
    """
    site_escaped = site_name.replace("'", "''")
    host_escaped = hostname.replace("'", "''")

    # Build binding info string
    binding_info = f"{ip}:{port}:{host_escaped}"

    script = f"""
Import-Module WebAdministration -ErrorAction Stop

# Remove existing HTTPS binding if present
$existing = Get-WebBinding -Name '{site_escaped}' -Protocol 'https' `
    -IPAddress '{ip}' -Port {port} -HostHeader '{host_escaped}' -ErrorAction SilentlyContinue
if ($existing) {{
    Remove-WebBinding -Name '{site_escaped}' -Protocol 'https' `
        -IPAddress '{ip}' -Port {port} -HostHeader '{host_escaped}'
}}

# Create new HTTPS binding
New-WebBinding -Name '{site_escaped}' -Protocol 'https' `
    -IPAddress '{ip}' -Port {port} -HostHeader '{host_escaped}'

# Assign the certificate
$binding = Get-WebBinding -Name '{site_escaped}' -Protocol 'https' `
    -IPAddress '{ip}' -Port {port} -HostHeader '{host_escaped}'
$binding.AddSslCertificate('{thumbprint}', '{store_name}')

Write-Output 'SUCCESS'
"""

    stdout, stderr, rc = _run_powershell(script)

    if rc != 0:
        return False, f"Failed to bind certificate: {stderr}"

    if "SUCCESS" in stdout:
        return True, f"Certificate bound to {site_name} on {ip}:{port}"
    else:
        return False, f"Unexpected output: {stdout} {stderr}"


def remove_ssl_binding(
    site_name: str,
    ip: str = "*",
    port: int = 443,
    hostname: str = "",
) -> tuple[bool, str]:
    """Remove an HTTPS binding from an IIS site."""
    site_escaped = site_name.replace("'", "''")
    host_escaped = hostname.replace("'", "''")

    script = f"""
Import-Module WebAdministration -ErrorAction Stop
Remove-WebBinding -Name '{site_escaped}' -Protocol 'https' `
    -IPAddress '{ip}' -Port {port} -HostHeader '{host_escaped}'
Write-Output 'REMOVED'
"""

    stdout, stderr, rc = _run_powershell(script)

    if rc != 0:
        return False, f"Failed to remove binding: {stderr}"

    return True, "HTTPS binding removed."


def restart_iis_site(site_name: str) -> tuple[bool, str]:
    """Stop and start an IIS site."""
    site_escaped = site_name.replace("'", "''")

    script = f"""
Import-Module WebAdministration -ErrorAction Stop
Stop-Website -Name '{site_escaped}' -ErrorAction SilentlyContinue
Start-Website -Name '{site_escaped}'
Write-Output 'RESTARTED'
"""

    stdout, stderr, rc = _run_powershell(script)

    if rc != 0:
        return False, f"Failed to restart site: {stderr}"

    return True, f"Site '{site_name}' restarted."
