# proc_dump

ProcDump is a compact Windows process memory acquisition tool intended for digital forensics and security research. It extracts the memory of a running process into a .dmp file for offline analysis with tools such as Volatility, PE-sieve, or standard command-line utilities.

## Key features

- Lightweight, single-binary C++ tool
- Uses native Windows APIs (OpenProcess, ReadProcessMemory)
- Produces .dmp files suitable for forensic analysis
- Minimal external dependencies — built with MSVC / Visual Studio

## Requirements

- Windows 10 or later (x64)
- Microsoft Visual Studio (MSVC) or Visual Studio Build Tools
- Administrator privileges to access another process's memory

## Project layout

```
proc_dump/
├── proc_dump.sln            # Visual Studio solution
├── proc_dump/               # Project sources and config
│   ├── proc_dump.cpp        # Main source file
│   └── proc_dump.vcxproj    # Project file
└── x64/Release/             # Output after building (x64 Release)
		└── proc_dump.exe
```

## Build (CLI)

Open the "Developer Command Prompt for VS" (or a Visual Studio x64 developer prompt) and run:

```bash
cd C:\Users\<username>\Desktop\dump\proc_dump
msbuild proc_dump.sln /p:Configuration=Release /p:Platform=x64
```

If the build succeeds you will see a "Build succeeded" message and the binary will be at:

```
x64\Release\proc_dump.exe
```

## Usage

Important: Run the command prompt as Administrator. Without elevated privileges the tool may fail with "Access is denied.".

Basic usage (dump a process by PID):

```bash
cd x64\Release
proc_dump.exe <process_id> <output_path>
# Example:
proc_dump.exe 1234 C:\dumps\chrome_memory.dmp
```

Notes:
- <process_id> is the numeric PID of the target process.
- <output_path> is the full path where the .dmp file will be written. Ensure the target directory exists and you have write permissions.

## Examples

- Dump Chrome (PID 4321) to C:\dumps\chrome.dmp:

```bash
proc_dump.exe 4321 C:\dumps\chrome.dmp
```

## Troubleshooting

- "Access is denied":
	- Ensure you run as Administrator.
	- Check that no security product (antivirus/EDR) is blocking the tool.
	- Confirm the target process is running and not a protected process.

- Cannot open output file:
	- Verify the target output folder exists and is writable.

## Forensic analysis suggestions

- Analyze the resulting .dmp with Volatility: plugin selection depends on the type of dump.
- Use `strings` and PE analysis tools (PE-sieve) for quick artifact discovery.

## Roadmap / Future improvements

- GUI for interactive process selection
- Optional compression of dumps
- Hashing (SHA256/MD5) for integrity verification
- Live process enumeration and friendly process name lookup

## License

This project is released under the MIT License. See `LICENSE.txt` for details.

## Author

Salman Mallah — Security Engineer & Researcher
GitHub: @salmanmallah

---

