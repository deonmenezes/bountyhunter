# MANTISHACK + Claude Code Quick Start

## TL;DR
Use MANTISHACK with plain English in Claude Code via slash commands!

## Commands

| Command | Use Case | Example |
|---------|----------|---------|
| `/mantishack` | General help | `/mantishack - I want to test my app` |
| `/mantis-scan`   | Scan source code | `/mantis-scan - check this repo for bugs` |
| `/mantis-fuzz`   | Fuzz binaries | `/mantis-fuzz - test ./myapp for crashes` |
| `/mantis-web`    | Test web apps | `/mantis-web - scan https://myapp.com` |

## Natural Language Examples

Just talk naturally to Claude:

### Code Scanning
```
/mantis-scan - scan this directory
/mantis-scan - find secrets in my code
/mantis-scan - check for SQL injection vulnerabilities
```

### Binary Fuzzing
```
/mantis-fuzz - fuzz this binary
/mantis-fuzz - test ./myapp for 5 minutes
/mantis-fuzz - find crashes in /usr/local/bin/myapp
```

### Web Testing
```
/mantis-web - test my website
/mantis-web - scan https://localhost:3000 for XSS
/mantis-web - check this app for OWASP Top 10
```

### General
```
/mantishack - scan my code for vulnerabilities
/mantishack - I need to fuzz a binary
/mantishack - help me test my application
```

## What Claude Does

1. ✅ Understands your request in plain English
2. ✅ Runs the appropriate MANTISHACK command
3. ✅ Analyzes the results
4. ✅ Explains vulnerabilities found
5. ✅ Shows generated exploits and patches
6. ✅ Offers to help fix issues

## Interactive Workflow

```
You: /mantis-scan - scan this code

Claude: I'll scan the current directory with MANTISHACK...
        [Runs scan...]
        Found 5 vulnerabilities!

        1. SQL Injection (CRITICAL) - api/db.py:23
           Generated exploit: out/exploits/sqli_001.py
           Generated patch: out/patches/sqli_001.patch

        Would you like me to:
        1. Apply the patches?
        2. Explain the SQL injection?
        3. Show the exploit code?

You: Show me the exploit

Claude: [Reads and displays the exploit code]
        This exploit works by...

You: Apply the patch for that one

Claude: [Applies the patch using Edit tool]
        ✓ Patch applied! The SQL injection is now fixed.

        Want me to scan again to verify the fix?
```

## Benefits

🎯 **No command-line syntax to remember**
🤖 **AI understands your intent**
📊 **Results explained in plain English**
🔧 **Interactive fix workflow**
⚡ **Fast and autonomous**

## Setup (Through Claude Code)

```bash
# 1. Clone and open in Claude Code
git clone https://github.com/gadievron/raptor.git
cd mantishack
claude

# 2. Let Claude handle setup
"Install Python packages from requirements.txt"
"Install semgrep"  # External tool

# 3. Set up LLM (choose one)
"Set my ANTHROPIC_API_KEY to [your-key]"          # Cloud (best quality)
# OR
"Install Ollama and pull deepseek-r1 model"       # Local/free

# 4. Start using MANTISHACK
/mantis-scan - Scan code for vulnerabilities
/mantis-fuzz - Fuzz binaries (asks to install AFL++ if needed)
/mantis-web  - Test web applications
```

**Optional tools** (Claude Code helps install when you use them):
- AFL++ (for fuzzing)
- CodeQL (for deep static analysis)
- LLDB/GDB (for crash analysis - LLDB pre-installed on macOS)

Let Claude Code handle it!

## Examples by Scenario

### "I just cloned a new repo and want to check it"
```
/mantis-scan - scan this repository for all security issues
```

### "I have a binary and want to find bugs"
```
/mantis-fuzz - fuzz ./myapp for 30 minutes
```

### "I want to test my web app before deploying"
```
/mantis-web - test http://localhost:8000
```

### "I'm not sure what I need"
```
/mantishack - help me secure my application
```

---

**That's it!** Just use `/mantishack` commands and chat naturally with Claude.

Claude Code will handle:
- Running MANTISHACK commands
- Interpreting results
- Explaining vulnerabilities
- Applying fixes
- Answering questions

No more memorizing command-line flags! 🎉
