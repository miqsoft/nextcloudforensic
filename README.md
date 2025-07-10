# Nextcloud Forensics Toolkit

A comprehensive forensics toolkit for Nextcloud instances that provides capabilities similar to The Sleuth Kit (TSK) but specifically designed for Nextcloud environments. This toolkit enables forensic investigators to extract, analyze, and examine data from Nextcloud servers in a structured and systematic manner.

## Overview

The Nextcloud Forensics Toolkit consists of a main Python module (`nextcloud_forensics`) and four command-line utilities inspired by The Sleuth Kit:

- **`nc-fls`**: File listing utility (similar to TSK's `fls`)
- **`nc-icat`**: File content extraction utility (similar to TSK's `icat`)
- **`nc-istat`**: File metadata inspection utility (similar to TSK's `istat`)
- **`nc-fsstat`**: File system statistics utility (similar to TSK's `fsstat`)

## Features

### Core Functionality
- **Complete file system enumeration** with recursive directory traversal
- **Deleted file recovery** from Nextcloud trashbin
- **File content extraction** by file ID with version support
- **Comprehensive metadata analysis** including forensic timeline information
- **Activity logging** for all file operations and user actions
- **Version history tracking** for file changes over time
- **Sharing relationship analysis** for data access patterns
- **User and device management** for access control investigation
- **Full data acquisition** with structured output

### Security Features
- **App password management** with revocation capabilities
- **Device authorization tracking** and remote revocation
- **Authentication token analysis** for security investigations
- **SSL certificate verification** with configurable warnings
- **Proxy support** for network-isolated environments
- **Comprehensive logging** of all API interactions

## Installation

### Prerequisites

- Python 3.6+
- Valid Nextcloud server credentials (username and app password)
- Network access to the target Nextcloud instance

### Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `requests>=2.25.1`
- `colorama>=0.4.4`
- `beautifulsoup4>=4.10.0`
- `colorlog>=6.7.0`

## Usage

### Main Tool (`nextcloud.py`)

The main forensics tool provides comprehensive data extraction and analysis capabilities:

```bash
python nextcloud.py --url https://nextcloud.example.com --username user --password app_password --action [ACTION]
```

#### Available Actions

| Action | Description |
|--------|-------------|
| `user-info` | Extract user profile information and quota details |
| `server-capabilities` | Analyze server configuration and installed applications |
| `trash-bin` | Examine deleted files and directories |
| `list-files` | Enumerate active file system with metadata |
| `file-activity` | Retrieve comprehensive activity logs for specific files |
| `file-id-to-path` | Resolve file paths from unique file identifiers |
| `download-file` | Extract file content by ID with version support |
| `shares` | Analyze sharing relationships and permissions |
| `list-users` | Enumerate server users (requires admin privileges) |
| `search-user` | Search for specific users with detailed information |
| `revoke-app-password` | Revoke application passwords for security |
| `file-versions` | Examine version history for specific files |
| `list-devices` | Enumerate authorized devices (requires user password) |
| `revoke-device` | Revoke device authorization remotely |
| `dump` | Complete data acquisition with structured output |

#### Example Usage

```bash
# Extract user information
python nextcloud.py --url https://nc.example.com --username user --password pass --action user-info

# List all files recursively
python nextcloud.py --url https://nc.example.com --username user --password pass --action list-files --recursive

# Examine file activity
python nextcloud.py --url https://nc.example.com --username user --password pass --action file-activity --file-id 12345

# Complete data acquisition
python nextcloud.py --url https://nc.example.com --username user --password pass --action dump --include-deleted
```

### TSK-Style Utilities

#### `nc-fls` - File System Listing

Lists files and directories in a format similar to TSK's `fls` command:

```bash
# List root directory
./nc-fls --url https://nc.example.com --username user --password pass

# Recursive listing with deleted files
./nc-fls --url https://nc.example.com --username user --password pass -r -d

# List specific directory
./nc-fls --url https://nc.example.com --username user --password pass /Documents
```

**Features:**
- Recursive directory traversal (`-r`)
- Deleted file inclusion (`-d`)
- File ID and metadata display
- Color-coded output for different file types

#### `nc-icat` - File Content Extraction

Extracts file content by file ID, similar to TSK's `icat`:

```bash
# Extract file content to stdout
./nc-icat --url https://nc.example.com --username user --password pass 12345

# Extract to specific file
./nc-icat --url https://nc.example.com --username user --password pass --output evidence.txt 12345

# Extract specific version
./nc-icat --url https://nc.example.com --username user --password pass 12345@1642534800
```

**Features:**
- Direct file ID access
- Version-specific content extraction
- Binary file support
- Stdout redirection support

#### `nc-istat` - File Metadata Analysis

Displays comprehensive metadata for files by ID, similar to TSK's `istat`:

```bash
# Basic metadata display
./nc-istat --url https://nc.example.com --username user --password pass 12345

# Full activity history
./nc-istat --url https://nc.example.com --username user --password pass --full-activity 12345

# Raw JSON output
./nc-istat --url https://nc.example.com --username user --password pass --raw 12345
```

**Features:**
- Complete file metadata
- Activity timeline analysis
- Version history tracking
- Sharing relationship details
- Raw JSON output option

#### `nc-fsstat` - File System Statistics

Displays general information about the Nextcloud instance, similar to TSK's `fsstat`:

```bash
# Basic system information
./nc-fsstat --url https://nc.example.com --username user --password pass

# Verbose output with detailed capabilities
./nc-fsstat --url https://nc.example.com --username user --password pass --verbose

# Raw JSON output
./nc-fsstat --url https://nc.example.com --username user --password pass --raw
```

**Features:**
- Server version and capabilities
- Instance configuration details
- User information and quota
- File system features status
- Security capabilities overview
- Administrative user count (if accessible)

## Advanced Features

### Proxy Support

All tools support proxy configuration for network-isolated environments:

```bash
python nextcloud.py --proxy http://proxy.example.com:8080 [other options]
```

### SSL Configuration

```bash
# Enable SSL verification
python nextcloud.py --verify-ssl [other options]

# Show SSL warnings
python nextcloud.py --show-ssl-warnings [other options]
```

### Logging and Debugging

Comprehensive logging capabilities for forensic documentation:

```bash
# Enable detailed API logging
python nextcloud.py --log-file investigation.log [other options]

# Verbose output
python nextcloud.py --verbose [other options]
```

### Data Acquisition

The `dump` action creates a complete forensic acquisition:

```bash
python nextcloud.py --url https://nc.example.com --username user --password pass --action dump --include-deleted --dump-dir /evidence
```

**Output Structure:**
```
nextcloud_dump_20240101_120000/
├── _metadata/
│   ├── acquisition_info.json
│   ├── user_info.json
│   ├── server_capabilities.json
│   ├── file_listing.json
│   └── summary.json
└── files/
    ├── [reconstructed directory structure]
    └── [file contents with original names]
```

## API Coverage

The toolkit leverages the following Nextcloud APIs:

### User Data
- `ocs/v2.php/cloud/user` - Personal user metadata
- `ocs/v1.php/cloud/users` - User directory listing
- `ocs/v2.php/cloud/users/details` - User search results

### Server Information
- `ocs/v1.php/cloud/capabilities` - Server configuration

### File System Data
- `remote.php/dav/files/{username}` - Active file system
- `remote.php/dav/trashbin/{username}/trash` - Deleted items
- `remote.php/dav/versions/{username}/versions/{file_id}` - Version history

### Activity and Sharing
- `ocs/v2.php/apps/activity/api/v2/activity/filter` - Activity history
- `ocs/v2.php/apps/files_sharing/api/v1/shares` - Sharing relationships

### Security
- `ocs/v2.php/core/apppassword` - Authentication management
- `settings/personal/authtokens/{device_id}` - Device authorization

## File ID Format

The toolkit uses a special file ID format for versioned files:
- `fileid` - Current version of the file
- `fileid@timestamp` - Specific version at given timestamp

## Security Considerations

1. **App Passwords**: Use dedicated app passwords instead of user passwords
2. **Network Security**: Consider using proxy settings in secure environments
3. **SSL Verification**: Enable SSL verification for production environments
4. **Logging**: Secure log files as they contain sensitive API interactions
5. **Data Handling**: Follow forensic best practices for evidence preservation

## Limitations

- Requires valid Nextcloud credentials
- Some features require administrative privileges
- Device management requires user password (not app password)
- Performance depends on server response times
- Large file downloads may timeout

## Contributing

This toolkit is designed for forensic investigations and security research. Please ensure compliance with applicable laws and regulations when using this software.

## License

This project is intended for educational and forensic purposes. Use responsibly and in accordance with applicable laws.

## Support

For issues and feature requests, please refer to the project documentation or contact the development team.