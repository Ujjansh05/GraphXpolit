# Getting started

GraphXploit runs on a local source directory. It creates an index outside the project, then answers impact and dependency queries from that index. Scan a project before querying it.

## Windows

1. Download and extract `graphxploit-windows-x86_64.zip` from the repository Releases page.
2. Open PowerShell in the extracted folder.
3. Run `./graphxploit.exe --help` to confirm that it starts.

```powershell
.\graphxploit.exe scan "C:\Users\you\source\my-project"
.\graphxploit.exe impact "C:\Users\you\source\my-project" "src/auth.py::login"
```

## Linux

```bash
unzip graphxploit-linux-x86_64.zip
chmod +x graphxploit
./graphxploit --help
./graphxploit scan /home/you/source/my-project
```

## Dashboard

```powershell
.\graphxploit.exe serve "C:\Users\you\source\my-project"
```

The command prints a local address such as `http://127.0.0.1:49152`. Open that address in an existing browser. Select **Scan project**, then enter a symbol or fully qualified name and choose **Impact** or **Dependencies**.

## Try the included sample

When building from this repository, the following commands use the safe sample project included in `data/sample_code`:

```powershell
.\target\release\graphxploit.exe scan .\data\sample_code
.\target\release\graphxploit.exe impact .\data\sample_code "auth.py::authenticate"
```

## Where data is stored

GraphXploit stores an SQLite index per project in the normal local application-data directory. Set `GRAPHXPLOIT_DATA_DIR` before running a command to choose another parent directory.

```powershell
$env:GRAPHXPLOIT_DATA_DIR = "D:\GraphXploitData"
.\graphxploit.exe scan "D:\source\my-project"
```

The index is generated metadata. Deleting the `GraphXploit/projects` directory under that location removes all indexes; a later scan rebuilds them.
