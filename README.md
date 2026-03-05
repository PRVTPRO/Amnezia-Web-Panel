# Amnezia Web Panel

A modern, high-performance web interface for simplified management of AmneziaWG and Xray (XTLS-Reality) servers. Designed to provide a premium user experience with robust administrative capabilities.

![Interface Preview](https://github.com/user-attachments/assets/preview_placeholder.png)

## 🚀 Key Features

*   **⚡ Multi-Protocol Support**:
    *   **AmneziaWG**: Advanced WireGuard-based protocol with S3/S4 obfuscation to bypass deep packet inspection (DPI).
    *   **Xray (XTLS-Reality)**: Stealthy protocol that masks VPN traffic as standard HTTPS browsing.
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
*   **📤 Data Interoperability**:
    *   **Remnawave Sync**: Automatically import and sync users from Remnawave.
    *   **Simple Backup**: Effortless JSON-based export and restore of all panel data.
*   **🔗 Public Sharing**:
    *   Generate password-protected links for users to download their configurations without panel access.

## 🏗 Prerequisites

*   **Python 3.10+**
*   Target servers: **Ubuntu 20.04/22.04/24.04** (Architecture: x86_64 or ARM64).
*   SSH access to target servers (Password or Private Key).

## 📦 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/amnezia-vpn/amnezia-client.git
    cd amnezia-client/web-panel
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
