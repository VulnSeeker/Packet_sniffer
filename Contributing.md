# Contributing Guidelines

First off, thank you for considering contributing to Packet Sniffer! 🎉

## 📋 How to Contribute

1. **Fork** the repository
2. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open a Pull Request**

## 🛠️ Development Setup

```bash
# Clone your fork
git clone https://github.com/VulnSeeker/Packet_sniffer.git
cd Packet_sniffer

# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate      # Linux/macOS
# venv\Scripts\activate       # Windows

# Install in development mode
pip install -e .
```

📝 Code Style

· Follow PEP 8 guidelines
· Use meaningful variable names
· Add comments for complex logic
· Keep functions focused and small
· Update documentation for new features

🧪 Testing

```bash
# Install test dependencies
pip install pytest flake8

# Run tests
python -m pytest tests/

# Check code style
flake8 packet_sniffer.py
```

🔄 Pull Request Process

1. Update README.md with details of changes (if needed)
2. Update requirements.txt if you added dependencies
3. Ensure all tests pass locally
4. Get review from at least one maintainer
5. Wait for merge – we'll review as soon as possible!

🐛 Reporting Issues

Found a bug? Have a suggestion?

1. Check if the issue already exists
2. If not, open a new issue
3. Include:
   · Your operating system
   · Python version (python --version)
   · Error messages (if any)
   · Steps to reproduce

💬 Need Help?

· Open an issue with the label question
· Reach out to maintainers

---

Thank you for helping make Packet Sniffer better! 🚀
