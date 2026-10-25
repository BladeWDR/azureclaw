# Bare-Metal Secure Boot Guide (systemd-boot + sbctl)

This guide documents how to configure **UEFI Secure Boot** on bare-metal router hardware (e.g., Protectli, Topton, Intel N100 appliances) using **`systemd-boot`** and **`sbctl`**.

---

## 1. Why `sbctl` instead of MOK / Shim?

Traditional Linux distributions use **`shim`** to chainload GRUB. `shim` implements a software layer called MOK (Machine Owner Key) because typical consumer PCs come with Microsoft keys locked into the motherboard firmware.

Because Azureclaw uses **`systemd-boot`** for instant reboots and minimal attack surface, it boots directly from the UEFI firmware without `shim`. Instead of MOK, `systemd-boot` uses native UEFI firmware signature databases:
- **PK (Platform Key)**: Root of trust for the motherboard.
- **KEK (Key Exchange Key)**: Authorizes updates to the signature database.
- **db (Signature Database)**: Whitelist of hashes and certificates authorized to execute at boot.

`sbctl` (Secure Boot Control) is the modern, user-friendly tool to manage these native UEFI keys directly from Linux.

---

## 2. Prerequisites

1. **Bare-metal appliance booted with UEFI (OVMF or native UEFI firmware)**.
2. `sbctl` and `sbsigntools` are pre-installed in the Azureclaw container image.
3. Physical access to your router's BIOS/UEFI setup screen.

---

## 3. Step-by-Step Enrollment Guide

### Step 1: Put Motherboard into UEFI "Setup Mode"
To allow Linux to write custom keys into the motherboard's NVRAM, you must clear the factory keys:

1. Reboot your router appliance and enter the BIOS setup menu (typically by pressing `Del`, `F2`, or `F11`).
2. Navigate to the **Security** or **Boot** -> **Secure Boot** menu.
3. Set **Secure Boot Mode** to **Custom** (if available).
4. Select **"Clear Secure Boot Keys"**, **"Delete all Secure Boot variables"**, or **"Reset to Setup Mode"**.
5. Save changes and reboot into Azureclaw.

---

### Step 2: Verify Setup Mode in Azureclaw
Log in to your router over SSH or local console and check Secure Boot status:

```bash
sudo sbctl status
```

Expected output:
```text
Installed:	✗ sbctl is not installed
Setup Mode:	✓ Enabled
Secure Boot:	✗ Disabled
```
*(The key requirement is that **Setup Mode** shows **Enabled**).*

---

### Step 3: Generate Custom Encryption Keys
Create your local cryptographic certificate authority and keys:

```bash
sudo sbctl create-keys
```
This generates your unique PK, KEK, and db certificates in `/usr/share/secureboot/keys/`.

---

### Step 4: Enroll Keys (Including Microsoft Option ROMs)
Enroll your keys into the motherboard NVRAM:

```bash
sudo sbctl enroll-keys -m
```

> [!IMPORTANT]
> **Why the `-m` flag is critical on routers:**
> The `-m` flag includes Microsoft's UEFI CA certificate in your `db`. Many router hardware components (such as Intel I225/I226 multi-gig PCIe network cards and integrated GPUs) contain **UEFI Option ROMs** that are signed by Microsoft. If you omit `-m`, your network cards or display output may fail to initialize during POST.

---

### Step 5: Sign the Bootloader and Kernel Files
Identify which boot binaries need signing:

```bash
sudo sbctl verify
```

Sign the `systemd-boot` EFI executable and tell `sbctl` to remember the file (`-s` flag):

```bash
# 1. Sign systemd-boot binary
sudo sbctl sign -s /boot/efi/EFI/systemd/systemd-bootx64.efi

# 2. Sign the bootc fallback loader (if present)
sudo sbctl sign -s /boot/efi/EFI/BOOT/BOOTX64.EFI

# 3. Sign all installed kernels
sudo sbctl sign-all -g
```

Verify that all binaries are now signed:
```bash
sudo sbctl verify
```
Expected output:
```text
✓ /boot/efi/EFI/BOOT/BOOTX64.EFI is signed
✓ /boot/efi/EFI/systemd/systemd-bootx64.efi is signed
```

---

### Step 6: Enable Secure Boot and Reboot
1. Reboot the router into your BIOS settings:
   ```bash
   systemctl reboot --firmware-setup
   ```
2. In the BIOS **Secure Boot** menu, change **Secure Boot** from *Disabled* to **Enabled**.
3. Save changes and exit.
4. Once booted into Azureclaw, verify that full enforcement is active:
   ```bash
   sudo sbctl status
   ```

Expected final status:
```text
Installed:	✓ sbctl is installed
Owner GUID:	<your-guid>
Setup Mode:	✗ Disabled
Secure Boot:	✓ Enabled
Vendor Keys:	microsoft
```

Your Azureclaw router is now running with hardware-enforced cryptographic Secure Boot with zero dependencies on GRUB or third-party shims.

---

## 4. Emergency Recovery

If you ever encounter an `Access Denied` or boot signature error after a manual intervention:
1. Enter the BIOS setup.
2. Select **"Clear Secure Boot Keys"** to return the firmware to **Setup Mode**.
3. Boot Azureclaw and re-run `sudo sbctl sign-all -g && sudo sbctl enroll-keys -m`.
