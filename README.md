# Amnezia Web Panel

A modern, high-performance web interface for simplified management of AmneziaWG and Xray (XTLS-Reality) servers. Designed to provide a premium user experience with robust administrative capabilities.

> ### 🔄 Compatibility with Official Amnezia Client
> 
> This panel is fully compatible with the official **Amnezia** applications!
> 
> **How to connect an existing server:**
> 1. Add your pre-configured server by entering its **IP address**, **login** and **password**
> 2. Go to the "Added Servers" section
> 3. Wait for the automatic server verification
> 4. The panel will automatically detect:
>    - ✅ Installed protocols
>    - ✅ Existing users
>    - ✅ Current configuration
>
> ⚡ **After verification, you can manage the server directly from the panel!**

## ⚠️ Legal Notice

> **This project is created solely for educational and research purposes.**
>
> **This project has never been intended for use in jurisdictions where the technologies employed are prohibited.** The author bears no responsibility for any unlawful use of this software.

**This project merely adds an abstraction layer for managing publicly available applications.** All applications belong to their respective owners. This project does not claim ownership over, nor does it modify, any third-party applications.

The use of traffic obfuscation tools may violate the laws of your country. Only use this software for lawful purposes, such as:

- **Penetration testing and security research**
- **CTF (Capture The Flag) competitions**
- **Academic and scientific research**
- **Testing and securing your own networks**
- **Improving defensive security measures**
- **Educational training in cybersecurity**

> **Nothing in this project constitutes an incitement to violate any applicable laws.**

![Servers Dashboard](https://github.com/PRVTPRO/Amnezia-Web-Panel/blob/main/screen/panel1.png)


### Additional Sections

<details>
<summary><b>👥 Users Management</b> (click to expand)</summary>
<br>
User management interface with permissions and access controls:

![Users Management](https://github.com/PRVTPRO/Amnezia-Web-Panel/blob/main/screen/panel1-2.png)
</details>

<details>
<summary><b>⚙️ System Settings</b> (click to expand)</summary>
<br>
Configuration panel for system parameters and preferences:

![Settings Panel](https://github.com/PRVTPRO/Amnezia-Web-Panel/blob/main/screen/panel1-3.png)
</details>

## 🚀 Key Features

*   **⚡ Multi-Protocol Support**:
    *   **AmneziaWG**: Advanced WireGuard-based protocol with S3/S4 obfuscation to bypass deep packet inspection (DPI).
    *   **Classic WireGuard**: Standard, high-performance WireGuard protocol for unmatched speed and broad device compatibility with traffic monitoring support.
    *   **Xray (XTLS-Reality)**: Stealthy protocol that masks VPN traffic as standard HTTPS browsing. Supports dynamic SNI mapping configuration overrides.
    *   **Telemt (Telegram Proxy)**: High-performance Telegram MTProxy with TLS emulation and comprehensive management (quotas, IP limits, and real-time session tracking).
    *   **AmneziaDNS**: Internal DNS resolver overriding default behavior to prevent DNS leaks and blockings.
*   **⚙️ Core Server Management**:
    *   Reboot servers and perform full Amnezia software cleanup directly from the UI.
    *   Lightning-fast, strictly concurrent protocol status polling for immediate feedback.
    *   **Asynchronous Processing**: Resilient, non-blocking background architecture prevents the UI panel from freezing, even if remote endpoints hang.
*   **🌐 Internationalization (i18n)**:
    *   Full support for **English**, **Russian**, **French**, **Chinese**, and **Persian**.
    *   Native **RTL (Right-to-Left)** support for Persian language.
*   **👥 Advanced User Management**:
    *   Role-based access (Admin, Support, Regular User).
    *   Traffic limits, status monitoring, and account expiration.
    *   One-click user enabling/disabling.
*   **🎨 Premium UI/UX**:
    *   Stunning glassmorphism design.
    *   Dynamic **Dark/Light** mode transition.
    *   Fully responsive for mobile and desktop.
*   **🤖 Telegram Bot Integration**:
    *   Notify users about new connections or limits.
    *   Integrated management via Telegram commands.
*   **🔄 Built-in Update Checker**:
    *   View your current panel version directly in Settings.
    *   One-click check for fresh GitHub releases to stay up to date.
*   **📤 Data Interoperability**:
    *   **Remnawave Sync**: Automatically import and sync users from Remnawave.
    *   **Simple Backup**: Effortless JSON-based export and restore of all panel data.
*   **🔗 Public Sharing**:
    *   Generate password-protected links for users to download their configurations without panel access.

## 💡 Need Additional Functionality?

If you require any custom features not currently available in the panel, **let us know – we'll implement them quickly!** 

* **Database Support**: PostgreSQL, MySQL/MariaDB, SQLite, Oracle, and MS SQL Server
* **In-Panel File Editor**: Edit configuration files inside containers directly from the web interface
* **Backup & Restore nodes/protocols**: Comprehensive backup solutions for nodes and protocols
* **Protocol Migration**: Seamlessly move protocols between nodes
* **Xray Self-Steal Mode**: Advanced Xray configuration with self-steal functionality
* **And much more!**

**Or better yet, contribute!**


## 🏗 Prerequisites

*   **Python 3.10+**
*   Target servers: **Ubuntu 20.04/22.04/24.04** (Architecture: x86_64 or ARM64).
*   SSH access to target servers (Password or Private Key).

## 📦 Installation 

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/PRVTPRO/Amnezia-Web-Panel.git
    cd Amnezia-Web-Panel
    ```

2.  **Set up Virtual Environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
## 🚀 Getting Started

Launch the application:

```bash
python app.py
```

The panel will be accessible at `http://localhost:5000`.

## 📦 Installation Method 2

Download and run the executable file for your system.
```
Windows
Linux
Mac
```

## 🐳 Docker Image

https://hub.docker.com/r/prvtpro/amnezia-panel


### Initial Login
*   **Username**: `admin`
*   **Password**: `admin`
> [!IMPORTANT]  
> Secure your panel by changing the default password in the **Users** section immediately after first login.

## 🔧 Project Details

### API Documentation
The project includes self-documenting API endpoints:
*   **Swagger UI**: `/docs`
*   **ReDoc**: `/redoc`

> **Note:** The current API is designed exclusively for internal panel operations (requires session authentication). A dedicated public REST API for external integrations is not yet available and would need to be implemented.

### Technology Stack
*   **Backend**: FastAPI (Python)
*   **Frontend**: Vanilla JS, Jinja2, Custom CSS (Glassmorphism)
*   **Database**: Local JSON storage (`data.json`)
*   **SSH Engine**: Paramiko

## 🛡 Security Recommendations

*   **Reverse Proxy**: It is highly recommended to run the panel behind Nginx/Apache with an SSL certificate.
*   **SSH Keys**: Use SSH keys rather than passwords for connecting to your VPN servers.
*   **Secret Key**: Set a custom `SECRET_KEY` environment variable for secure session management.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit Pull Requests or open Issues for feature requests and bug reports.

## 📄 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](../LICENSE) file for details.

---
*Built with ❤️ for the Amnezia community.*
