# 🔐 Abdal 4iProto Server SSH KeyGen

<div align="right">
  <img src="scr.jpg" alt="Abdal 4iProto Server SSH KeyGen"  >
</div>

A powerful and interactive SSH key generation tool with beautiful progress bar and user-friendly interface.

## 📘 Other Languages

- [🇮🇷 Persian - فارسی](README.fa.md)


## 🌟 Features

### ✨ Interactive Mode
- **Algorithm Selection Menu**: Choose from RSA, ED25519, or ECDSA encryption algorithms
- **Beautiful Progress Bar**: Real-time animated progress bar using Bubbletea
- **Overwrite Confirmation**: Smart confirmation dialog when files already exist
- **Smooth Animations**: Professional UI with color-coded messages
- **Wait for User Input**: Pauses before exit to show results
- **Automatic File Naming**: Files are automatically named based on selected algorithm

### ⚡ Non-Interactive Mode
- **Command Line Arguments**: Full support for all traditional flags
- **Algorithm Selection**: Choose algorithm via `-t` flag (rsa, ed25519, ecdsa)
- **Force Overwrite**: `-force` flag to overwrite existing files
- **Custom Key Size**: Configurable key bit size based on algorithm
- **Custom Output**: Flexible file naming and comments
- **Automatic File Naming**: Files are automatically named based on selected algorithm

### 🎨 User Experience
- **Color-Coded Messages**: Green for success, red for errors, orange for warnings
- **Professional Styling**: Clean terminal UI with proper spacing
- **Responsive Design**: Adapts to different terminal sizes
- **Emoji Icons**: Visual feedback for better user experience

## 🚀 Installation

### Prerequisites
- Go 1.24.0 or later
- Git

### Build from Source
```bash
git clone https://github.com/ebrasha/abdal-4iproto-server-ssh-keygen.git
cd abdal-4iproto-server-ssh-keygen
go mod tidy
go build -o abdal-4iproto-server-ssh-keygen .
```
 
## 📖 Usage

### Interactive Mode (Recommended)
Simply run the program without any arguments:

```bash
./abdal-4iproto-server-ssh-keygen
```

**What happens:**
1. 🔐 **Algorithm Selection**: Choose encryption algorithm (RSA, ED25519, or ECDSA)
   - Use ↑/↓ arrow keys or j/k to navigate
   - Press Enter or Space to select
   - Press q to quit
2. 🔍 Checks for existing key files
3. ⚠️ Shows confirmation dialog if files exist
4. 📊 Displays beautiful progress bar during generation
5. ✅ Shows success message with file details
6. ⌨️ Waits for any key press to exit

**Algorithm Selection Navigation:**
- **↑ or k**: Move selection up
- **↓ or j**: Move selection down
- **Enter or Space**: Select algorithm
- **q**: Quit program

### Non-Interactive Mode
Use command line arguments for automation:

```bash
# Generate RSA key (default)
./abdal-4iproto-server-ssh-keygen -t rsa -b 4096

# Generate ED25519 key
./abdal-4iproto-server-ssh-keygen -t ed25519

# Generate ECDSA key with P-256
./abdal-4iproto-server-ssh-keygen -t ecdsa -b 256

# Generate ECDSA key with P-384
./abdal-4iproto-server-ssh-keygen -t ecdsa -b 384

# Generate key with custom filename
./abdal-4iproto-server-ssh-keygen -t ed25519 -f my_key

# Generate key with comment
./abdal-4iproto-server-ssh-keygen -t ecdsa -b 521 -C "server@example.com"

# Force overwrite existing files
./abdal-4iproto-server-ssh-keygen -t rsa -b 2048 -force -f existing_key
```

### Command Line Options

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `-t` | Key type/algorithm: rsa, ed25519, or ecdsa | rsa | `-t ed25519` |
| `-b` | Key size in bits (RSA: 2048,3072,4096,8192 \| ECDSA: 256,384,521) | 4096 | `-b 2048` |
| `-f` | Output filename for private key (auto-named if not specified) | id_rsa/id_ed25519/id_ecdsa | `-f my_key` |
| `-C` | Key comment | "" | `-C "user@host"` |
| `-force` | Overwrite existing files | false | `-force` |

## 🔐 Supported Encryption Algorithms

The tool supports multiple encryption algorithms:

### RSA (Rivest-Shamir-Adleman)
- **Key Sizes**: 2048, 3072, 4096, 8192 bits
- **Default**: 4096 bits
- **Best For**: Maximum compatibility with older systems
- **File Names**: `id_rsa` / `id_rsa.pub`

### ED25519 (Edwards-curve Digital Signature Algorithm)
- **Key Size**: 256 bits (fixed)
- **Best For**: Modern systems, fast and secure
- **File Names**: `id_ed25519` / `id_ed25519.pub`

### ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Key Sizes**: P-256, P-384, P-521
- **Default**: P-256
- **Best For**: Modern systems, efficient and secure
- **File Names**: `id_ecdsa` / `id_ecdsa.pub`

 

 

## 🛠️ Technical Details

### Dependencies
- **Bubbletea**: Interactive terminal UI framework
- **Bubbles**: UI components (progress bar)
- **Lipgloss**: Terminal styling and colors
- **Go Crypto**: SSH key generation and encoding
- **golang.org/x/crypto/ed25519**: ED25519 key generation
- **golang.org/x/crypto/ssh**: SSH key encoding and formatting



## 🐛 Reporting Issues
If you encounter any issues or have configuration problems, please reach out via email at Prof.Shafiei@Gmail.com. You can also report issues on GitHub.

## ❤️ Donation
If you find this project helpful and would like to support further development, please consider making a donation:
- [Donate Here](https://ebrasha.com/abdal-donation)

## 🤵 Programmer
Handcrafted with Passion by **Ebrahim Shafiei (EbraSha)**
- **E-Mail**: Prof.Shafiei@Gmail.com
- **Telegram**: [@ProfShafiei](https://t.me/ProfShafiei)

## 📜 License
This project is licensed under the GPLv2 or later License. 