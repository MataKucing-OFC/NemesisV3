# NemesisToolz

Security research toolkit by **MataKucing** and **Team Nemesis**.

GitHub: [github.com/MataKucing-OFC](https://github.com/MataKucing-OFC)

> Use this toolkit only on systems you own or are explicitly authorized to test.

## Features

- Host, IP, subdomain, DNS, OSINT, port, and TXT tools.
- Unified CVE tools menu.
- Centralized CVE configuration through `settings.json`.
- Target input through `list.txt`.
- Results saved in the `result/` directory.

## Requirements

- Python 3.9 or newer
- Network access for tools that query remote targets

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Run the main menu from the project directory:

```bash
python3 main.py
```

Choose **11. CVE Tools** to run a CVE module. The selected tool starts
directly using the shared configuration and returns to the CVE menu when it
finishes.

## Configuration

Edit [`settings.json`](settings.json) before using CVE tools:

```json
{
  "target_list": "list.txt",
  "username": "your_username",
  "password": "your_password",
  "email": "you@example.com",
  "thread": 50
}
```

`target_list` points to a text file in the project directory. Put one domain
or URL per line in [`list.txt`](list.txt). Domains without a protocol are
treated as `http://domain.tld`.

## Output

Results are written to [`result/`](result). CVE modules use filenames based on
their CVE identifier, such as:

```text
result/CVE-2025-11533.txt
result/CVE-2025-15030.txt
result/CVE-2026-0920.txt
```

## Project Structure

```text
NemesisToolz/
├── main.py
├── modules/
├── list.txt
├── settings.json
├── requirements.txt
└── result/
```

## Notes

- Existing module logic is kept in `modules/`; the main menu provides the
  launcher and shared configuration.
- Do not commit real credentials to a public repository. Replace example
  values in `settings.json` with local values and protect the file.
