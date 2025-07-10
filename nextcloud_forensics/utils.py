from colorama import Fore, Back, Style, init
from datetime import datetime
import json
import logging
import sys
import os
import colorlog


# Initialize colorama
init(autoreset=True)

class NextcloudLogger:
    """Class for handling forensic logging of Nextcloud API requests"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls, log_file=None):
        """Singleton pattern to ensure we always use the same logger instance"""
        if cls._instance is None:
            cls._instance = cls(log_file)
        elif log_file and cls._instance.log_file != log_file:
            # Update log file if it changed
            cls._instance.add_file_handler(log_file)
        return cls._instance
    
    def __init__(self, log_file=None):
        """Initialize logger with optional file output"""
        self.logger = logging.getLogger('nextcloud_forensics')
        self.logger.setLevel(logging.DEBUG)
        self.log_file = log_file
        
        # Clear existing handlers to avoid duplicate logs on re-initialization
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        
        # Console handler with nice formatting
        console_handler = colorlog.StreamHandler(stream=sys.stdout)
        console_handler.setLevel(logging.ERROR)
        
        # Create formatter
        formatter = colorlog.ColoredFormatter(
            fmt='%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%d-%m-%y %H:%M:%S',
            reset=True,
            log_colors={
                'DEBUG':    'cyan',
                'INFO':     'green',
                'WARNING':  'bold_yellow',
                'ERROR':    'bold_red',
                'CRITICAL': 'bold_red',
            },
            secondary_log_colors={},
            style='%'
        )
        
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Add file handler if specified
        if log_file:
            self.add_file_handler(log_file)
    
    def add_file_handler(self, log_file):
        """Add or update file handler for the logger"""
        self.log_file = log_file
        
        # Remove existing file handlers
        for handler in self.logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                self.logger.removeHandler(handler)
        
        # Create directory for log file if it doesn't exist
        log_dir = os.path.dirname(os.path.abspath(log_file))
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Add new file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Create a standard non-colored formatter for the file
        file_formatter = logging.Formatter(
            fmt='[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%d-%m-%y %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
    
    def log_request(self, method, url, **kwargs):
        """Log a request being made to the Nextcloud server"""
        message = f"REQUEST: {method.upper()} {url}"
        
        # Log request parameters while sanitizing sensitive data
        params = kwargs.get('params')
        if params:
            sanitized_params = params.copy()
            if 'password' in sanitized_params:
                sanitized_params['password'] = '********'
            message += f" Params: {sanitized_params}"
            
        self.logger.info(message)
        return message
    
    def log_response(self, response):
        """Log a response from the Nextcloud server"""
        message = f"RESPONSE: {response.status_code} {response.reason} - {response.url}"
        
        # Log response time if available
        if hasattr(response, 'elapsed'):
            message += f" - Time: {response.elapsed.total_seconds():.3f}s"
            
        self.logger.info(message)
        
        # Log detailed information at debug level
        if response.status_code >= 400:
            self.logger.debug(f"Response error details: {response.text[:500]}...")
        
        return message

    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
        
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
        
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
        
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
        
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)


class NextcloudUtils:
    @staticmethod
    def format_size(size_bytes):
        """
        Converts bytes to human-readable format
        """
        if size_bytes <= 0:
            return "Unlimited"
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        i = 0
        while size_bytes >= 1024 and i < len(units) - 1:
            size_bytes /= 1024
            i += 1
        return f"{size_bytes:.2f} {units[i]}"

    @staticmethod
    def display_user_info(user_data: dict) -> None:
        """
        Displays user information from the Nextcloud server in a 
        well-formatted, colorized structure.
        """
        try:
            # Check if the response is successful
            meta = user_data.get('ocs', {}).get('meta', {})
            if meta.get('statuscode') != 200:
                print(f"{Fore.RED}Error: {meta.get('message', 'Unknown error')}")
                return
                
            # Extract user data
            data = user_data.get('ocs', {}).get('data', {})
            if not data:
                print(f"{Fore.RED}Error: No user data found in the response")
                return
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud User Information {Style.RESET_ALL}\n")
            
            # Basic user info section
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Basic Information ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Username:       {Fore.WHITE}{data.get('id', 'N/A')}")
            print(f"{Fore.GREEN}Display Name:   {Fore.WHITE}{data.get('displayname', 'N/A')}")
            print(f"{Fore.GREEN}Email:          {Fore.WHITE}{data.get('email', 'N/A')}")
            print(f"{Fore.GREEN}Language:       {Fore.WHITE}{data.get('language', 'N/A')}")
            print(f"{Fore.GREEN}Locale:         {Fore.WHITE}{data.get('locale', 'N/A')}")
            
            # Last login information
            if data.get('lastLogin'):
                timestamp = int(data.get('lastLogin', 0)) // 1000  # Convert from milliseconds to seconds
                last_login = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{Fore.GREEN}Last Login:     {Fore.WHITE}{last_login}")
            
            # Storage information
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Storage Information ==={Style.RESET_ALL}")
            quota = data.get('quota', {})
            
            if quota:
                used = quota.get('used', 0)
                total = quota.get('quota', 0)
                
                used_formatted = NextcloudUtils.format_size(used)
                
                if total == -3:  # -3 means unlimited quota in Nextcloud
                    total_formatted = "Unlimited"
                    percentage = 0
                else:
                    total_formatted = NextcloudUtils.format_size(total)
                    percentage = (used / total * 100) if total > 0 else 0
                
                print(f"{Fore.GREEN}Storage Used:   {Fore.WHITE}{used_formatted}")
                print(f"{Fore.GREEN}Storage Total:  {Fore.WHITE}{total_formatted}")
                
                if total != -3:  # Only show percentage if not unlimited
                    # Color code based on percentage used
                    color = Fore.GREEN
                    if percentage > 70:
                        color = Fore.YELLOW
                    if percentage > 90:
                        color = Fore.RED
                        
                    print(f"{Fore.GREEN}Usage:          {color}{percentage:.1f}%")
                
                print(f"{Fore.GREEN}Storage Path:   {Fore.WHITE}{data.get('storageLocation', 'N/A')}")
            
            # Additional information
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Additional Information ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Organization:   {Fore.WHITE}{data.get('organisation', 'N/A')}")
            print(f"{Fore.GREEN}Phone:          {Fore.WHITE}{data.get('phone', 'N/A')}")
            print(f"{Fore.GREEN}Website:        {Fore.WHITE}{data.get('website', 'N/A')}")
            
            # Group memberships
            if data.get('groups'):
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Group Memberships ==={Style.RESET_ALL}")
                for group in data.get('groups', []):
                    print(f"{Fore.GREEN}- {Fore.WHITE}{group}")
                    
            # Admin roles
            if data.get('subadmin'):
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Admin Roles ==={Style.RESET_ALL}")
                for role in data.get('subadmin', []):
                    print(f"{Fore.GREEN}- {Fore.WHITE}{role}")
                    
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying user information: {str(e)}{Style.RESET_ALL}")
            
    @staticmethod
    def display_capabilities(capabilities_data: dict) -> None:
        """
        Displays server capabilities information from the Nextcloud server
        in a well-formatted, colorized structure.
        """
        try:
            # Check if the response is successful
            meta = capabilities_data.get('ocs', {}).get('meta', {})
            if meta.get('status') != 'ok':
                print(f"{Fore.RED}Error: {meta.get('message', 'Unknown error')}")
                return
                
            # Extract capabilities data
            data = capabilities_data.get('ocs', {}).get('data', {})
            if not data:
                print(f"{Fore.RED}Error: No capabilities data found in the response")
                return
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud Server Capabilities {Style.RESET_ALL}\n")
            
            # Version information section
            version = data.get('version', {})
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Version Information ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Version:        {Fore.WHITE}{version.get('string', 'N/A')}")
            print(f"{Fore.GREEN}Edition:        {Fore.WHITE}{version.get('edition', 'N/A')}")
            print(f"{Fore.GREEN}Major:          {Fore.WHITE}{version.get('major', 'N/A')}")
            print(f"{Fore.GREEN}Minor:          {Fore.WHITE}{version.get('minor', 'N/A')}")
            print(f"{Fore.GREEN}Micro:          {Fore.WHITE}{version.get('micro', 'N/A')}")
            print(f"{Fore.GREEN}Extended:       {Fore.WHITE}{version.get('extendedSupport', False)}")
            
            # Extract capabilities
            capabilities = data.get('capabilities', {})
            
            # Core capabilities
            core = capabilities.get('core', {})
            if core:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Core Capabilities ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}Poll Interval:  {Fore.WHITE}{core.get('pollinterval', 'N/A')}")
                print(f"{Fore.GREEN}WebDAV Root:    {Fore.WHITE}{core.get('webdav-root', 'N/A')}")
                print(f"{Fore.GREEN}Mod Rewrite:    {Fore.WHITE}{core.get('mod-rewrite-working', False)}")
                print(f"{Fore.GREEN}Reference API:  {Fore.WHITE}{core.get('reference-api', False)}")
            
            # Files capabilities
            files = capabilities.get('files', {})
            if files:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Files Capabilities ==={Style.RESET_ALL}")
                
                # Blacklisted/Forbidden files
                forbidden_files = files.get('forbidden_filenames', files.get('blacklisted_files', []))
                if forbidden_files:
                    print(f"{Fore.GREEN}Forbidden Files:{Style.RESET_ALL}")
                    for file in forbidden_files:
                        print(f"{Fore.GREEN}  - {Fore.WHITE}{file}")
                
                # Forbidden extensions
                forbidden_exts = files.get('forbidden_filename_extensions', [])
                if forbidden_exts:
                    print(f"{Fore.GREEN}Forbidden Extensions:{Style.RESET_ALL}")
                    for ext in forbidden_exts:
                        print(f"{Fore.GREEN}  - {Fore.WHITE}{ext}")
                
                # Other capabilities
                print(f"{Fore.GREEN}Versioning:     {Fore.WHITE}{files.get('versioning', False)}")
                print(f"{Fore.GREEN}Comments:       {Fore.WHITE}{files.get('comments', False)}")
                print(f"{Fore.GREEN}Undelete:       {Fore.WHITE}{files.get('undelete', False)}")
                print(f"{Fore.GREEN}Delete Trash:   {Fore.WHITE}{files.get('delete_from_trash', False)}")
                
                # Chunked Upload info
                chunked_upload = files.get('chunked_upload', {})
                if chunked_upload:
                    print(f"{Fore.GREEN}Chunked Upload:  {Style.RESET_ALL}")
                    max_size = chunked_upload.get('max_size', 0)
                    print(f"{Fore.GREEN}  Max Size:     {Fore.WHITE}{NextcloudUtils.format_size(max_size)}")
                    print(f"{Fore.GREEN}  Max Parallel: {Fore.WHITE}{chunked_upload.get('max_parallel_count', 'N/A')}")
            
            # File sharing capabilities
            sharing = capabilities.get('files_sharing', {})
            if sharing:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Sharing Capabilities ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}API Enabled:    {Fore.WHITE}{sharing.get('api_enabled', False)}")
                print(f"{Fore.GREEN}Resharing:      {Fore.WHITE}{sharing.get('resharing', False)}")
                print(f"{Fore.GREEN}Group Sharing:  {Fore.WHITE}{sharing.get('group_sharing', False)}")
                
                # Public sharing
                public = sharing.get('public', {})
                if public:
                    print(f"{Fore.GREEN}Public Sharing: {Fore.WHITE}{public.get('enabled', False)}")
                    print(f"{Fore.GREEN}  Upload:       {Fore.WHITE}{public.get('upload', False)}")
                    print(f"{Fore.GREEN}  Files Drop:   {Fore.WHITE}{public.get('upload_files_drop', False)}")
                    print(f"{Fore.GREEN}  Password Req: {Fore.WHITE}{public.get('password', {}).get('enforced', False)}")
                    print(f"{Fore.GREEN}  Expire Dates: {Fore.WHITE}{public.get('expire_date', {}).get('enabled', False)}")
                
                # Federation
                federation = sharing.get('federation', {})
                if federation:
                    print(f"{Fore.GREEN}Federation:     {Style.RESET_ALL}")
                    print(f"{Fore.GREEN}  Outgoing:     {Fore.WHITE}{federation.get('outgoing', False)}")
                    print(f"{Fore.GREEN}  Incoming:     {Fore.WHITE}{federation.get('incoming', False)}")
            
            # Theming capabilities
            theming = capabilities.get('theming', {})
            if theming:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Theming Information ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}Name:           {Fore.WHITE}{theming.get('name', 'N/A')}")
                print(f"{Fore.GREEN}URL:            {Fore.WHITE}{theming.get('url', 'N/A')}")
                print(f"{Fore.GREEN}Slogan:         {Fore.WHITE}{theming.get('slogan', 'N/A')}")
                print(f"{Fore.GREEN}Color:          {Fore.WHITE}{theming.get('color', 'N/A')}")
                
            # User status capabilities
            user_status = capabilities.get('user_status', {})
            if user_status:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== User Status Features ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}Enabled:        {Fore.WHITE}{user_status.get('enabled', False)}")
                print(f"{Fore.GREEN}Restore:        {Fore.WHITE}{user_status.get('restore', False)}")
                print(f"{Fore.GREEN}Emoji Support:  {Fore.WHITE}{user_status.get('supports_emoji', False)}")
            
            # Other significant capabilities summary
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Other Capabilities ==={Style.RESET_ALL}")
            if 'notifications' in capabilities:
                print(f"{Fore.GREEN}Notifications:  {Fore.WHITE}Supported")
            
            if 'password_policy' in capabilities:
                policy = capabilities.get('password_policy', {})
                min_length = policy.get('minLength', 'N/A')
                print(f"{Fore.GREEN}Password Policy:{Fore.WHITE} Min Length: {min_length}")
            
            if 'circles' in capabilities:
                print(f"{Fore.GREEN}Circles:        {Fore.WHITE}Supported")
                
            if 'app_api' in capabilities:
                print(f"{Fore.GREEN}App API:        {Fore.WHITE}Version {capabilities.get('app_api', {}).get('version', 'N/A')}")
            
            # Note about full capabilities
            print(f"\n{Fore.YELLOW}Note: This is a summary of key capabilities. Use --output-json with this command to get full details.{Style.RESET_ALL}")
            
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying capabilities: {str(e)}{Style.RESET_ALL}")
            
    @staticmethod
    def display_trashbin(trash_items: list) -> None:
        """
        Displays trash bin contents from the Nextcloud server in a 
        well-formatted, colorized structure that maintains folder hierarchy.
        """
        try:
            if not trash_items:
                print(f"{Fore.YELLOW}The trash bin is empty.{Style.RESET_ALL}")
                return
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud Trash Bin Contents {Style.RESET_ALL}\n")
            
            # Sort items by deletion time (most recent first)
            sorted_items = sorted(trash_items, key=lambda x: x.get('deletion_time', 0), reverse=True)
            
            # Group items by deletion date
            date_groups = {}
            for item in sorted_items:
                if 'deletion_time' not in item:
                    continue
                    
                # Convert timestamp to date string
                timestamp = item['deletion_time']
                date_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
                
                if date_str not in date_groups:
                    date_groups[date_str] = []
                    
                date_groups[date_str].append(item)
            
            # Print items by date group
            for date_str, items in date_groups.items():
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Deleted on {date_str} ==={Style.RESET_ALL}")
                
                # Process each item in the current date group
                for item in items:
                    # File/folder name with appropriate icon
                    icon = "📁 " if item.get('is_collection', False) else "📄 "
                    name = item.get('displayname', 'Unknown')
                    
                    # Determine color based on item type
                    name_color = Fore.BLUE if item.get('is_collection', False) else Fore.WHITE
                    
                    # Original location and path
                    original_path = item.get('original_location', name)
                    
                    # Get file type or indicate it's a folder
                    if item.get('is_collection', False):
                        type_info = "Folder"
                    else:
                        content_type = item.get('contenttype', 'Unknown')
                        # Simplify content type for display
                        if '/' in content_type:
                            type_info = content_type.split('/')[-1].upper()
                        else:
                            type_info = content_type
                    
                    # Format file size
                    size_str = NextcloudUtils.format_size(item.get('size', 0))
                    
                    # Format deletion time with hours and minutes
                    deletion_time = datetime.fromtimestamp(item.get('deletion_time', 0)).strftime('%H:%M:%S')
                    
                    # Print the item with all its details
                    print(f"{icon}{name_color}{name}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Type:     {Fore.WHITE}{type_info}")
                    print(f"  {Fore.GREEN}Size:     {Fore.WHITE}{size_str}")
                    print(f"  {Fore.GREEN}Time:     {Fore.WHITE}{deletion_time}")
                    print(f"  {Fore.GREEN}Original: {Fore.WHITE}{original_path}")
                    if item.get('fileid'):
                        print(f"  {Fore.GREEN}File ID:  {Fore.WHITE}{item.get('fileid')}")
                    print()
            
            # Summary stats
            total_files = sum(1 for item in trash_items if not item.get('is_collection', False))
            total_folders = sum(1 for item in trash_items if item.get('is_collection', False))
            total_size = sum(item.get('size', 0) for item in trash_items)
            
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Summary ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Files:    {Fore.WHITE}{total_files}")
            print(f"{Fore.GREEN}Total Folders:  {Fore.WHITE}{total_folders}")
            print(f"{Fore.GREEN}Total Size:     {Fore.WHITE}{NextcloudUtils.format_size(total_size)}")
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying trash bin: {str(e)}{Style.RESET_ALL}")
            
    @staticmethod
    def save_json_to_file(data: dict, filename: str) -> None:
        """
        Saves JSON data to a file with pretty formatting.
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            print(f"{Fore.GREEN}Data saved to {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error saving data to file: {str(e)}{Style.RESET_ALL}")
            
    @staticmethod
    def display_files(file_items: list, recursive: bool = False) -> None:
        """
        Displays files and directories from the Nextcloud server in a 
        simplified tree structure showing only names.
        
        Args:
            file_items: List of file/directory items from the server
            recursive: Whether to display files in a tree structure (default: False)
        """
        try:
            if not file_items:
                print(f"{Fore.YELLOW}No files found.{Style.RESET_ALL}")
                return
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud Files {Style.RESET_ALL}\n")
            
            # Get the path we're displaying
            current_path = "/"
            if file_items and 'path' in file_items[0]:
                parent_path = file_items[0]['path']
                # If we're not at root, get the parent directory
                if parent_path != "/" and parent_path.count('/') > 1:
                    current_path = '/'.join(parent_path.split('/')[:-1]) or '/'
            
            print(f"{Fore.CYAN}{Style.BRIGHT}Directory: {current_path}{Style.RESET_ALL}\n")
            
            if recursive:
                # Create a dictionary to represent the file system structure
                file_system = {}
                
                # Process each item in the file_items list
                for item in file_items:
                    path = item.get('path', '')
                    if not path:
                        continue
                    
                    # Strip leading/trailing slashes and split into path components
                    path = path.strip('/')
                    if not path:  # Skip root
                        continue
                        
                    parts = path.split('/')
                    
                    # Navigate the tree structure
                    current = file_system
                    for i, part in enumerate(parts):
                        if i == len(parts) - 1:
                            # This is the leaf node (file or directory)
                            current[part] = {
                                'item': item,
                                'children': {}
                            }
                        else:
                            # This is a directory in the path
                            if part not in current:
                                current[part] = {
                                    'children': {}
                                }
                            current = current[part]['children']
                
                # Helper function to print the file system tree
                def print_tree(node, prefix='', is_last=True):
                    # Sort items: directories first, then files, all alphabetically
                    items = sorted(node.items(), 
                                  key=lambda x: (
                                      'item' in x[1] and not x[1]['item'].get('is_collection', False),  # Files come after directories
                                      x[0].lower()  # Alphabetically by name
                                  ))
                    
                    # Process each item
                    for i, (name, content) in enumerate(items):
                        is_last_item = i == len(items) - 1
                        
                        # Determine if this is a directory or file
                        is_dir = False
                        file_id = None
                        
                        if 'item' in content:
                            is_dir = content['item'].get('is_collection', False)
                            file_id = content['item'].get('fileid', 'N/A')
                        else:
                            is_dir = True  # If no item, it's an intermediate directory
                        
                        # Format branch symbols for tree view
                        if is_last_item:
                            branch = '└── '
                            next_prefix = prefix + '    '
                        else:
                            branch = '├── '
                            next_prefix = prefix + '│   '
                        
                        # Set color based on type
                        name_color = Fore.BLUE if is_dir else Fore.WHITE
                        
                        # Print the item with appropriate formatting, including File ID
                        if file_id:
                            print(f"{prefix}{branch}{name_color}{name} ({Fore.CYAN}{file_id}{name_color}){Style.RESET_ALL}")
                        else:
                            print(f"{prefix}{branch}{name_color}{name}{Style.RESET_ALL}")
                        
                        # Process children if this is a directory
                        if content['children']:
                            print_tree(content['children'], next_prefix, is_last_item)
                
                # Start printing the tree from the root
                print_tree(file_system)
                
            else:
                # Non-recursive mode: flat list with just names
                # Sort items by type (directories first) then by name
                sorted_items = sorted(file_items[1:] if len(file_items) > 1 else file_items,  # Skip the first item if it's the directory itself
                                     key=lambda x: (not x.get('is_collection', False), 
                                                   x.get('displayname', '').lower()))
                
                # Process each item
                for item in sorted_items:
                    # File/folder name with appropriate color
                    name = item.get('displayname', 'Unknown')
                    file_id = item.get('fileid', 'N/A')
                    
                    # Determine color based on item type
                    name_color = Fore.BLUE if item.get('is_collection', False) else Fore.WHITE
                    
                    # Print name with file ID in round brackets
                    print(f"{name_color}{name} ({Fore.CYAN}{file_id}{name_color}){Style.RESET_ALL}")
            
            # Summary stats
            total_files = sum(1 for item in file_items if not item.get('is_collection', False))
            total_folders = sum(1 for item in file_items if item.get('is_collection', False))
            total_size = sum(item.get('size', 0) or item.get('contentlength', 0) for item in file_items)
            
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Summary ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Files:    {Fore.WHITE}{total_files}")
            print(f"{Fore.GREEN}Total Folders:  {Fore.WHITE}{total_folders}")
            print(f"{Fore.GREEN}Total Size:     {Fore.WHITE}{NextcloudUtils.format_size(total_size)}")
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying files: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            
    @staticmethod
    def display_fls(file_items: list, trash_items: list = None, recursive: bool = False) -> None:
        """
        Displays files and directories in a tree (fls) format, optionally including deleted items marked with '*'.
        """
        try:
            if not file_items and not trash_items:
                print(f"{Fore.YELLOW}No items found.{Style.RESET_ALL}")
                return

            # Merge active and deleted items
            combined = []
            for item in file_items:
                it = item.copy()
                it['deleted'] = False
                combined.append(it)
                
            # Track paths to avoid duplicate entries
            processed_paths = set()
            for item in combined:
                path = item.get('path', '')
                name = item.get('displayname', '')
                if path:
                    processed_paths.add(path + '/' + name)
            
            if trash_items:
                for t in trash_items:
                    # Get the complete original path including filename
                    original_path = t.get('original_location', '')
                    # Skip if this path is already processed (active file exists)
                    if original_path in processed_paths:
                        continue
                    # Add to the combined list
                    combined.append({
                        'path': '/'.join(original_path.split('/')[:-1]) if '/' in original_path else '',  # Parent directory path
                        'displayname': t.get('displayname', ''),
                        'is_collection': t.get('is_collection', False),
                        'fileid': t.get('fileid', None),
                        'deleted': True
                    })

            # Build tree structure
            tree = {}
            for item in combined:
                path = item.get('path', '').strip('/')
                name = item.get('displayname', '')
                
                # For deleted items, create the proper path
                if item.get('deleted', False):
                    parts = path.split('/') if path else []
                    if parts:  # If there's a path, use it to build the hierarchy
                        current = tree
                        # Navigate to the correct position in the tree
                        for i, part in enumerate(parts):
                            if i == len(parts) - 1 and not item.get('is_collection', False):
                                # If this is the last part of the path and not a directory,
                                # place the item here with its name
                                if part not in current:
                                    current[part] = {'children': {}}
                                current[part]['children'][name] = {'item': item, 'children': {}}
                            else:
                                # This is a directory in the path
                                if part not in current:
                                    current[part] = {'children': {}}
                                current = current[part]['children']
                        
                        # If path was empty, place at the root
                        if not parts:
                            tree[name] = {'item': item, 'children': {}}
                    else:
                        # No path, place at root
                        tree[name] = {'item': item, 'children': {}}
                else:
                    # For regular files, create the path normally
                    parts = path.split('/') if path else []
                    if parts:
                        current = tree
                        # Navigate to the correct position in the tree
                        for i, part in enumerate(parts):
                            if i == len(parts) - 1:
                                # This is the leaf node (file or directory)
                                if part not in current:
                                    current[part] = {'item': item, 'children': {}}
                                else:
                                    # Update the item if not a deleted one
                                    if 'item' not in current[part] or not current[part]['item'].get('deleted', False):
                                        current[part]['item'] = item
                            else:
                                # This is a directory in the path
                                if part not in current:
                                    current[part] = {'children': {}}
                                current = current[part]['children']
                    else:
                        # No path, place at root
                        tree[name] = {'item': item, 'children': {}}

            # Recursive print
            def print_tree(node, prefix=''):
                entries = sorted(node.items(), key=lambda x: (
                    'item' in x[1] and not x[1]['item'].get('is_collection', False),
                    x[0].lower()
                ))
                for idx, (name, content) in enumerate(entries):
                    is_last = idx == len(entries) - 1
                    branch = '└── ' if is_last else '├── '
                    next_pref = prefix + ('    ' if is_last else '│   ')
                    item = content.get('item', {})
                    is_dir = item.get('is_collection', False)
                    deleted = item.get('deleted', False)
                    file_id = item.get('fileid')
                    name_disp = name + ('*' if deleted else '')
                    name_color = Fore.BLUE if is_dir else Fore.WHITE
                    if file_id:
                        print(f"{prefix}{branch}{name_color}{name_disp} ({Fore.CYAN}{file_id}{name_color}){Style.RESET_ALL}")
                    else:
                        print(f"{prefix}{branch}{name_color}{name_disp}{Style.RESET_ALL}")
                    if content.get('children'):
                        print_tree(content['children'], next_pref)

            # Header
            print(f"\n{Style.BRIGHT}Nextcloud fls tree{' (recursive)' if recursive else ''}{Style.RESET_ALL}\n")
            print_tree(tree)
            print()
        except Exception as e:
            print(f"{Fore.RED}Error displaying fls tree: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            
    @staticmethod
    def display_file_activity(activity_data: dict) -> None:
        """
        Displays activity history for a specific file or directory from the Nextcloud server
        in a well-formatted, colorized structure.
        
        Args:
            activity_data: Dictionary containing file activity data from the Nextcloud API
        """
        try:
            # Check if the response is successful
            meta = activity_data.get('ocs', {}).get('meta', {})
            if meta.get('status') != 'ok' or meta.get('statuscode') != 200:
                print(f"{Fore.RED}Error: {meta.get('message', 'Unknown error')}")
                return
                
            # Extract activity data
            activities = activity_data.get('ocs', {}).get('data', [])
            if not activities:
                print(f"{Fore.YELLOW}No activity found for this file.{Style.RESET_ALL}")
                return
                
            # Get file name from the first activity entry
            file_id = None
            file_name = None
            file_path = None
            
            if activities:
                first_activity = activities[0]
                file_id = first_activity.get('object_id')
                file_name = first_activity.get('object_name', '').split('/')[-1]
                file_path = first_activity.get('object_name', '')
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud File Activity {Style.RESET_ALL}\n")
            
            if file_name and file_path:
                print(f"{Fore.CYAN}{Style.BRIGHT}File: {Fore.WHITE}{file_name}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{Style.BRIGHT}Path: {Fore.WHITE}{file_path}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{Style.BRIGHT}File ID: {Fore.WHITE}{file_id}{Style.RESET_ALL}\n")
                
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Activity Timeline ==={Style.RESET_ALL}")
            
            # Track the file timeline
            current_name = None
            
            # Process each activity chronologically (from oldest to newest)
            for activity in reversed(activities):
                # Extract key information
                activity_type = activity.get('type', '')
                user = activity.get('user', 'Unknown')
                timestamp = activity.get('datetime', '')
                
                # Convert ISO timestamp to local datetime object
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    formatted_time = timestamp
                
                # Determine activity color based on type
                if 'created' in activity_type:
                    action_color = Fore.GREEN
                    action_icon = "+"
                elif 'changed' in activity_type:
                    action_color = Fore.YELLOW
                    action_icon = "✎"
                elif 'deleted' in activity_type:
                    action_color = Fore.RED
                    action_icon = "-"
                elif 'shared' in activity_type:
                    action_color = Fore.BLUE
                    action_icon = "⇌"
                else:
                    action_color = Fore.WHITE
                    action_icon = "•"
                
                # Print timestamp and user info
                print(f"{Fore.CYAN}{formatted_time} {Fore.MAGENTA}[{user}]{Style.RESET_ALL}")
                
                # Process activity based on type
                if activity.get('subject_rich'):
                    rich_data = activity.get('subject_rich', [])
                    
                    # Handle different types of activities with rich data
                    if 'file_created' in activity_type:
                        file_info = rich_data[1].get('file', {})
                        file_name = file_info.get('name', 'Unknown')
                        file_path = file_info.get('path', 'Unknown')
                        current_name = file_name
                        print(f"  {action_color}[{action_icon}] Created file: {file_name}{Style.RESET_ALL}")
                        print(f"  {Fore.WHITE}    Path: {file_path}{Style.RESET_ALL}")
                        
                    elif 'file_changed' in activity_type and 'umbenannt' in rich_data[0]:
                        # Rename operation
                        old_file = rich_data[1].get('oldfile', {})
                        new_file = rich_data[1].get('newfile', {})
                        old_name = old_file.get('name', 'Unknown')
                        new_name = new_file.get('name', 'Unknown')
                        current_name = new_name
                        print(f"  {action_color}[{action_icon}] Renamed file:{Style.RESET_ALL}")
                        print(f"  {Fore.WHITE}    From: {old_name}")
                        print(f"  {Fore.WHITE}    To:   {new_name}{Style.RESET_ALL}")
                        
                    elif 'file_changed' in activity_type:
                        # Generic file change
                        if 'file' in rich_data[1]:
                            file_info = rich_data[1].get('file', {})
                            file_name = file_info.get('name', 'Unknown')
                            print(f"  {action_color}[{action_icon}] Modified file: {file_name}{Style.RESET_ALL}")
                        else:
                            print(f"  {action_color}[{action_icon}] File was modified{Style.RESET_ALL}")
                            
                    elif 'file_deleted' in activity_type:
                        file_info = rich_data[1].get('file', {})
                        file_name = file_info.get('name', 'Unknown')
                        print(f"  {action_color}[{action_icon}] Deleted file: {file_name}{Style.RESET_ALL}")
                        
                    elif 'shared_user' in activity_type or 'shared_group' in activity_type:
                        file_info = rich_data[1].get('file', {})
                        file_name = file_info.get('name', 'Unknown')
                        shared_with = rich_data[1].get('user', {}).get('name', 'Unknown')
                        print(f"  {action_color}[{action_icon}] Shared file: {file_name}{Style.RESET_ALL}")
                        print(f"  {Fore.WHITE}    With: {shared_with}{Style.RESET_ALL}")
                        
                    else:
                        # Fallback for any other activity type with rich data
                        print(f"  {action_color}[{action_icon}] {activity.get('subject', 'Unknown activity')}{Style.RESET_ALL}")
                else:
                    # Fallback for activities without rich data
                    print(f"  {action_color}[{action_icon}] {activity.get('subject', 'Unknown activity')}{Style.RESET_ALL}")
                
                # Add a blank line between activities for readability
                print()
                
            # Print file history summary
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Summary ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}First Activity: {Fore.WHITE}{datetime.fromisoformat(activities[-1].get('datetime', '').replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{Fore.GREEN}Latest Activity: {Fore.WHITE}{datetime.fromisoformat(activities[0].get('datetime', '').replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{Fore.GREEN}Total Activities: {Fore.WHITE}{len(activities)}")
            print(f"{Fore.GREEN}Current Name: {Fore.WHITE}{current_name or file_name}")
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying file activity: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            
    @staticmethod
    def display_shares(shares_data: dict) -> None:
        """
        Displays shares information from the Nextcloud server in a 
        well-formatted, colorized structure.
        
        Args:
            shares_data: Dictionary containing shares data from the Nextcloud API
        """
        try:
            # Check if the response is successful
            meta = shares_data.get('ocs', {}).get('meta', {})
            if meta.get('status') != 'ok' or meta.get('statuscode') != 200:
                print(f"{Fore.RED}Error: {meta.get('message', 'Unknown error')}")
                return
                
            # Extract shares data
            shares = shares_data.get('ocs', {}).get('data', [])
            if not shares:
                print(f"{Fore.YELLOW}No shares found.{Style.RESET_ALL}")
                return
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud Shares Information {Style.RESET_ALL}\n")
            
            # Group shares by type: user, group, link, etc.
            share_types = {
                0: "User shares",
                1: "Group shares", 
                3: "Public link shares",
                4: "Email shares",
                6: "Federated cloud shares",
                7: "Circle shares",
                10: "Room shares"
            }
            
            type_groups = {}
            for share in shares:
                share_type = share.get('share_type')
                if share_type not in type_groups:
                    type_groups[share_type] = []
                type_groups[share_type].append(share)
            
            # Display counts by type
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Share Counts by Type ==={Style.RESET_ALL}")
            for share_type, shares_list in type_groups.items():
                type_name = share_types.get(share_type, f"Other type ({share_type})")
                print(f"{Fore.GREEN}{type_name}: {Fore.WHITE}{len(shares_list)}")
            print()
            
            # Process each share by type
            for share_type, shares_list in type_groups.items():
                type_name = share_types.get(share_type, f"Other type ({share_type})")
                print(f"{Fore.CYAN}{Style.BRIGHT}=== {type_name} ==={Style.RESET_ALL}")
                
                for share in shares_list:
                    # Common share properties
                    share_id = share.get('id', 'N/A')
                    owner = share.get('displayname_owner', share.get('uid_owner', 'N/A'))
                    file_path = share.get('path', 'N/A')
                    file_type = share.get('item_type', 'unknown')
                    
                    # Format created time
                    stime = share.get('stime', 0)
                    if stime:
                        created_time = datetime.fromtimestamp(stime).strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        created_time = 'N/A'
                    
                    # Format size
                    size = share.get('item_size', 0)
                    if size:
                        size_formatted = NextcloudUtils.format_size(size)
                    else:
                        size_formatted = 'N/A'
                    
                    # Icon based on item type
                    icon = "📁 " if file_type == "folder" else "📄 "
                    
                    # Get permissions as human readable string
                    perm_code = share.get('permissions', 0)
                    permissions = []
                    if perm_code & 1:  # Read
                        permissions.append("Read")
                    if perm_code & 2:  # Update
                        permissions.append("Update")
                    if perm_code & 4:  # Create
                        permissions.append("Create")
                    if perm_code & 8:  # Delete
                        permissions.append("Delete")
                    if perm_code & 16:  # Share
                        permissions.append("Share")
                    permissions_str = ", ".join(permissions) if permissions else "None"
                    
                    # Item name/path with color based on type
                    name_color = Fore.BLUE if file_type == "folder" else Fore.WHITE
                    print(f"{icon}{name_color}{file_path}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Share ID:    {Fore.WHITE}{share_id}")
                    print(f"  {Fore.GREEN}Owner:       {Fore.WHITE}{owner}")
                    print(f"  {Fore.GREEN}Created:     {Fore.WHITE}{created_time}")
                    
                    # Display specific info based on share type
                    if share_type == 0:  # User share
                        share_with = share.get('share_with', 'N/A')
                        share_with_displayname = share.get('share_with_displayname', share_with)
                        print(f"  {Fore.GREEN}Shared with: {Fore.WHITE}{share_with_displayname} ({share_with})")
                        
                    elif share_type == 1:  # Group share
                        print(f"  {Fore.GREEN}Shared with: {Fore.WHITE}Group: {share.get('share_with', 'N/A')}")
                        
                    elif share_type == 3:  # Public link share
                        token = share.get('token', 'N/A')
                        url = share.get('url', 'N/A')
                        password_protected = "Yes" if share.get('password', None) else "No"
                        
                        # Expiration info
                        expiration = share.get('expiration', None)
                        if expiration:
                            expiration_str = f"{Fore.YELLOW}{expiration}"
                        else:
                            expiration_str = f"{Fore.GREEN}No expiration"
                            
                        hide_download = "Yes" if share.get('hide_download', 0) == 1 else "No"
                        
                        print(f"  {Fore.GREEN}Link:        {Fore.CYAN}{url}{Style.RESET_ALL}")
                        print(f"  {Fore.GREEN}Token:       {Fore.WHITE}{token}")
                        print(f"  {Fore.GREEN}Password:    {Fore.WHITE}{password_protected}")
                        print(f"  {Fore.GREEN}Expiration:  {expiration_str}{Style.RESET_ALL}")
                        print(f"  {Fore.GREEN}Hide Downld: {Fore.WHITE}{hide_download}")
                    
                    # Common details for all share types
                    print(f"  {Fore.GREEN}Type:        {Fore.WHITE}{file_type}")
                    print(f"  {Fore.GREEN}Size:        {Fore.WHITE}{size_formatted}")
                    print(f"  {Fore.GREEN}Permissions: {Fore.WHITE}{permissions_str}")
                    
                    # File ID and parent
                    file_id = share.get('file_source', 'N/A')
                    parent_id = share.get('file_parent', 'N/A')
                    print(f"  {Fore.GREEN}File ID:     {Fore.WHITE}{file_id}")
                    if parent_id != 'N/A':
                        print(f"  {Fore.GREEN}Parent ID:   {Fore.WHITE}{parent_id}")
                    
                    print() # Extra line between shares
                
            # Summary stats
            total_shares = len(shares)
            total_user_shares = len(type_groups.get(0, []))
            total_public_shares = len(type_groups.get(3, []))
            
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Summary ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Shares:      {Fore.WHITE}{total_shares}")
            print(f"{Fore.GREEN}User Shares:       {Fore.WHITE}{total_user_shares}")
            print(f"{Fore.GREEN}Public Link Shares:{Fore.WHITE}{total_public_shares}")
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying shares: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            
    @staticmethod
    def display_all_users(all_users_response: dict, users_details: dict = None) -> None:
        """
        Displays information about all users from the Nextcloud server in a 
        well-formatted, colorized structure.
        
        Args:
            all_users_response: Dictionary containing the response from get_all_users()
            users_details: Optional dictionary containing detailed user info, keyed by username.
                        If not provided, only basic user list will be shown.
        """
        try:
            # Check if the response is successful
            meta = all_users_response.get('ocs', {}).get('meta', {})
            if meta.get('status') != 'ok':
                print(f"{Fore.RED}Error: {meta.get('message', 'Unknown error')}")
                return
                
            # Extract usernames list
            users_data = all_users_response.get('ocs', {}).get('data', {})
            users = users_data.get('users', [])
            
            if not users:
                print(f"{Fore.YELLOW}No users found.{Style.RESET_ALL}")
                return
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud Users Information {Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}Found {len(users)} users{Style.RESET_ALL}\n")
            
            # Display information for each user
            for username in users:
                print(f"{Fore.CYAN}{Style.BRIGHT}=== User: {username} ==={Style.RESET_ALL}")
                
                # Check if we have detailed information for this user
                if users_details and username in users_details:
                    user_details = users_details.get(username, {})
                    
                    # Extract user data from the details
                    user_data = user_details.get('ocs', {}).get('data', {}).get('users', {}).get(username, {})
                    
                    if not user_data:
                        print(f"{Fore.YELLOW}No detailed information available for {username}{Style.RESET_ALL}\n")
                        continue
                    
                    # Basic information section
                    print(f"{Fore.GREEN}Display Name:   {Fore.WHITE}{user_data.get('display-name', 'N/A')}")
                    print(f"{Fore.GREEN}Email:          {Fore.WHITE}{user_data.get('email') or 'N/A'}")
                    
                    # Account status (enabled/disabled)
                    enabled_status = user_data.get('enabled', True)
                    status_color = Fore.GREEN if enabled_status else Fore.RED
                    status_text = "Enabled" if enabled_status else "Disabled"
                    print(f"{Fore.GREEN}Status:         {status_color}{status_text}{Style.RESET_ALL}")
                    
                    # Login information
                    first_login = user_data.get('firstLoginTimestamp', -1)
                    if first_login > 0:
                        first_login_str = datetime.fromtimestamp(first_login).strftime('%Y-%m-%d %H:%M:%S')
                        print(f"{Fore.GREEN}First Login:    {Fore.WHITE}{first_login_str}")
                    else:
                        print(f"{Fore.GREEN}First Login:    {Fore.WHITE}Never")
                    
                    last_login = user_data.get('lastLoginTimestamp', -1)
                    if last_login > 0:
                        last_login_str = datetime.fromtimestamp(last_login).strftime('%Y-%m-%d %H:%M:%S')
                        print(f"{Fore.GREEN}Last Login:     {Fore.WHITE}{last_login_str}")
                    else:
                        print(f"{Fore.GREEN}Last Login:     {Fore.WHITE}Never")
                    
                    # Groups membership
                    groups = user_data.get('groups', [])
                    if groups:
                        print(f"{Fore.GREEN}Groups:         {Fore.WHITE}{', '.join(groups)}")
                        # Highlight admin status
                        if 'admin' in groups:
                            print(f"{Fore.RED}{Style.BRIGHT}*** Admin User ***{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}Groups:         {Fore.WHITE}None")
                    
                    # Storage information
                    quota = user_data.get('quota', {})
                    if quota:
                        used = quota.get('used', 0)
                        total = quota.get('quota', 0)
                        
                        used_formatted = NextcloudUtils.format_size(used)
                        
                        if total == -3:  # -3 means unlimited quota in Nextcloud
                            total_formatted = "Unlimited"
                        else:
                            total_formatted = NextcloudUtils.format_size(total)
                        
                        print(f"{Fore.GREEN}Storage:        {Fore.WHITE}{used_formatted} of {total_formatted}")
                        print(f"{Fore.GREEN}Storage Path:   {Fore.WHITE}{user_data.get('storageLocation', 'N/A')}")
                    
                    # Additional contact information if available
                    if user_data.get('phone'):
                        print(f"{Fore.GREEN}Phone:          {Fore.WHITE}{user_data.get('phone')}")
                    
                    if user_data.get('address'):
                        print(f"{Fore.GREEN}Address:        {Fore.WHITE}{user_data.get('address')}")
                    
                    if user_data.get('website'):
                        print(f"{Fore.GREEN}Website:        {Fore.WHITE}{user_data.get('website')}")
                    
                    if user_data.get('organisation'):
                        print(f"{Fore.GREEN}Organization:   {Fore.WHITE}{user_data.get('organisation')}")
                    
                    # Authentication backend
                    if user_data.get('backend'):
                        print(f"{Fore.GREEN}Auth Backend:   {Fore.WHITE}{user_data.get('backend')}")
                else:
                    # If we don't have detailed info, just display the username
                    print(f"{Fore.YELLOW}Only basic username information available. Provide user details for more information.{Style.RESET_ALL}")
                    
                print()  # Extra newline between users
            
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Summary ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Users: {Fore.WHITE}{len(users)}")
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying users: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            
    @staticmethod
    def display_istat(file_metadata: dict, activity_data: dict = None, versions_data: list = None) -> None:
        """
        Displays detailed metadata for a specific file or directory from the Nextcloud server
        in a well-formatted, colorized structure similar to istat from The Sleuth Kit.
        
        Args:
            file_metadata: Dictionary containing file metadata
            activity_data: Optional dictionary containing file activity data
            versions_data: Optional list containing file version history
        """
        try:
            if not file_metadata:
                print(f"{Fore.YELLOW}No metadata found for this file.{Style.RESET_ALL}")
                return
                
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud istat (nc-istat) Output {Style.RESET_ALL}\n")
            
            # Basic file information section
            print(f"{Fore.CYAN}{Style.BRIGHT}=== File Information ==={Style.RESET_ALL}")
            
            # File ID is the primary identifier
            file_id = file_metadata.get('fileid', 'Unknown')
            print(f"{Fore.GREEN}File ID:        {Fore.WHITE}{file_id}")
            
            # Display name and path
            name = file_metadata.get('displayname', 'Unknown')
            path = file_metadata.get('path', '')
            print(f"{Fore.GREEN}Name:           {Fore.WHITE}{name}")
            print(f"{Fore.GREEN}Path:           {Fore.WHITE}{path}")
            
            # File type
            content_type = file_metadata.get('contenttype', None)
            if content_type:
                print(f"{Fore.GREEN}Content Type:   {Fore.WHITE}{content_type}")
            
            # Size information
            size = file_metadata.get('size', file_metadata.get('contentlength', 0))
            print(f"{Fore.GREEN}Size:           {Fore.WHITE}{NextcloudUtils.format_size(size)} ({size} bytes)")
            
            # Time information section
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Timestamps ==={Style.RESET_ALL}")
            
            # Creation time
            if file_metadata.get('creation_time'):
                creation_time = datetime.fromtimestamp(file_metadata.get('creation_time')).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{Fore.GREEN}Created:        {Fore.WHITE}{creation_time}")
            
            # Last modified time
            if file_metadata.get('lastmodified'):
                print(f"{Fore.GREEN}Last Modified:  {Fore.WHITE}{file_metadata.get('lastmodified')}")
            
            # Upload time
            if file_metadata.get('upload_time'):
                upload_time = datetime.fromtimestamp(file_metadata.get('upload_time')).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{Fore.GREEN}Uploaded:       {Fore.WHITE}{upload_time}")
            
            # Owner information
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Ownership & Permissions ==={Style.RESET_ALL}")
            owner_id = file_metadata.get('owner_id', 'N/A')
            owner_name = file_metadata.get('owner_name', 'N/A')
            print(f"{Fore.GREEN}Owner ID:       {Fore.WHITE}{owner_id}")
            print(f"{Fore.GREEN}Owner Name:     {Fore.WHITE}{owner_name}")
            
            # Permission flags (interpret the permission string)
            permissions = file_metadata.get('permissions', '')
            perm_flags = []
            if 'R' in permissions: perm_flags.append("Read")
            if 'W' in permissions: perm_flags.append("Write")
            if 'D' in permissions: perm_flags.append("Delete")
            if 'N' in permissions: perm_flags.append("Rename")
            if 'S' in permissions: perm_flags.append("Share")
            if 'M' in permissions: perm_flags.append("Mount")
            if 'C' in permissions: perm_flags.append("Create")
            if 'G' in permissions: perm_flags.append("Download")
            
            if perm_flags:
                print(f"{Fore.GREEN}Permissions:    {Fore.WHITE}{', '.join(perm_flags)} ({permissions})")
            
            # Additional metadata
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Additional Metadata ==={Style.RESET_ALL}")
            is_dir = file_metadata.get('is_collection', False)
            print(f"{Fore.GREEN}Is Directory:   {Fore.WHITE}{'Yes' if is_dir else 'No'}")
            
            if file_metadata.get('favorite') is not None:
                print(f"{Fore.GREEN}Is Favorite:    {Fore.WHITE}{'Yes' if file_metadata.get('favorite') else 'No'}")
            
            if file_metadata.get('etag'):
                print(f"{Fore.GREEN}ETag:           {Fore.WHITE}{file_metadata.get('etag')}")
                
            # Version information if this is a versioned file
            if file_metadata.get('is_version'):
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Version Information ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}Version Timestamp: {Fore.WHITE}{file_metadata.get('version_timestamp', 'Unknown')}")
                print(f"{Fore.GREEN}Source:           {Fore.WHITE}Versioned File")
            elif file_metadata.get('source'):
                print(f"\n{Fore.GREEN}Source:           {Fore.WHITE}{file_metadata.get('source').capitalize()}")
                
            # Version data if provided
            if versions_data and len(versions_data) > 0:
                # Show version count in the additional metadata section
                print(f"{Fore.GREEN}Version Count:  {Fore.WHITE}{len(versions_data)}")
                
                # Display version details right after without additional header
                if len(versions_data) > 1:
                    # Calculate the longest timestamp for formatting
                    max_timestamp_len = max([len(str(v.get('timestamp', ''))) for v in versions_data]) if versions_data else 10
                    
                    print(f"\n{Fore.GREEN}{'Version History:'}")
                    print(f"{Fore.GREEN}{'Timestamp':<{max_timestamp_len+5}} {'Size':<12} {'Last Modified':<30}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}{'-' * (max_timestamp_len+5)} {'-' * 12} {'-' * 30}{Style.RESET_ALL}")
                    
                    # Process each version (skip current version at index 0)
                    for i, version in enumerate(versions_data):
                        timestamp = version.get('timestamp', 'Unknown')
                        
                        # Format size
                        size = version.get('size', version.get('contentlength', 0))
                        size_str = NextcloudUtils.format_size(size)
                        
                        # Format last modified
                        lastmod = version.get('lastmodified', 'Unknown')
                        
                        # Highlight the current version
                        if i == 0:
                            print(f"{Fore.YELLOW}{timestamp:<{max_timestamp_len+5}} {size_str:<12} {lastmod} (current){Style.RESET_ALL}")
                        else:
                            print(f"{Fore.WHITE}{timestamp:<{max_timestamp_len+5}} {size_str:<12} {lastmod}{Style.RESET_ALL}")
            
            # Activity history if provided
            if activity_data:
                activities = activity_data.get('ocs', {}).get('data', [])
                
                if activities:
                    # Print activity section header
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Activity Timeline ==={Style.RESET_ALL}")
                    
                    # Sort activities by datetime (newest first)
                    sorted_activities = activities.copy()
                    
                    # Display the total count
                    print(f"{Fore.GREEN}Total Activities: {Fore.WHITE}{len(sorted_activities)}")
                    print(f"{Fore.GREEN}Latest Activity: {Fore.WHITE}{datetime.fromisoformat(sorted_activities[0].get('datetime', '').replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"{Fore.GREEN}First Activity: {Fore.WHITE}{datetime.fromisoformat(sorted_activities[-1].get('datetime', '').replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Display summary list of activities (most recent first)
                    print(f"\n{Fore.GREEN}Activity Summary:{Style.RESET_ALL}")
                    
                    # Show only the 5 most recent activities for brevity
                    for idx, activity in enumerate(sorted_activities[:5]):
                        # Extract key information
                        activity_type = activity.get('type', '')
                        user = activity.get('user', 'Unknown')
                        timestamp = activity.get('datetime', '')
                        
                        # Format timestamp
                        try:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            formatted_time = timestamp
                        
                        # Determine activity color based on type
                        if 'created' in activity_type:
                            action_color = Fore.GREEN
                            action_icon = "+"
                        elif 'changed' in activity_type:
                            action_color = Fore.YELLOW
                            action_icon = "✎"
                        elif 'deleted' in activity_type:
                            action_color = Fore.RED
                            action_icon = "-"
                        elif 'shared' in activity_type:
                            action_color = Fore.BLUE
                            action_icon = "⇌"
                        else:
                            action_color = Fore.WHITE
                            action_icon = "•"
                        
                        # Get simplified activity description
                        description = activity.get('subject', 'Unknown activity')
                        
                        # Print summary line
                        print(f"{action_color}{action_icon} {formatted_time} {Fore.MAGENTA}[{user}]{action_color} {description}{Style.RESET_ALL}")
                    
                    # Add note if there are more activities
                    if len(sorted_activities) > 5:
                        print(f"\n{Fore.YELLOW}Note: Showing 5 of {len(sorted_activities)} activities. Use --full-activity for complete history.{Style.RESET_ALL}")
            
            print()  # Extra newline at the end
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying file metadata: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            
    @staticmethod
    def display_file_versions(versions_data: list) -> None:
        """
        Displays file version history from the Nextcloud server in a 
        well-formatted, colorized structure.
        
        Args:
            versions_data: List of version items retrieved from get_file_versions()
        """
        try:
            if not versions_data:
                print(f"{Fore.YELLOW}No version history found for this file.{Style.RESET_ALL}")
                return
                            
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud File Versions {Style.RESET_ALL}\n")
            
            # Get file info from one of the versions if possible
            file_path = None
            file_type = None
            if versions_data:
                # Extract file path from the href if available
                href = versions_data[0].get('href', '')
                if href:
                    # Parse out file ID from the href path
                    parts = href.split('/')
                    if len(parts) > 2:
                        file_id = parts[-2]  # The second last element is the file ID
                        print(f"{Fore.CYAN}{Style.BRIGHT}File ID: {Fore.WHITE}{file_id}{Style.RESET_ALL}")
                
                # Try to get the file type
                contenttype = versions_data[0].get('contenttype')
                if contenttype:
                    print(f"{Fore.CYAN}{Style.BRIGHT}File Type: {Fore.WHITE}{contenttype}{Style.RESET_ALL}")
            
            # Print version count
            print(f"{Fore.CYAN}{Style.BRIGHT}Total Versions: {Fore.WHITE}{len(versions_data)}{Style.RESET_ALL}\n")
            
            # Print version details
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Version History ==={Style.RESET_ALL}")
            
            # Calculate the longest timestamp to format table-like output
            max_timestamp_len = max([len(str(v.get('timestamp', ''))) for v in versions_data]) if versions_data else 10
            
            # Header row
            print(f"{Fore.GREEN}{'Version Timestamp':<{max_timestamp_len+5}} {'Size':<12} {'Last Modified':<30}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'-' * (max_timestamp_len+5)} {'-' * 12} {'-' * 30}{Style.RESET_ALL}")
            
            # Process each version
            for i, version in enumerate(versions_data):
                timestamp = version.get('timestamp', 'Unknown')
                
                # Format size
                size = version.get('size', version.get('contentlength', 0))
                size_str = NextcloudUtils.format_size(size)
                
                # Format last modified
                lastmod = version.get('lastmodified', 'Unknown')
                
                # Highlight the current version
                if i == 0:
                    print(f"{Fore.YELLOW}{timestamp:<{max_timestamp_len+5}} {size_str:<12} {lastmod}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.WHITE}{timestamp:<{max_timestamp_len+5}} {size_str:<12} {lastmod}{Style.RESET_ALL}")
            
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying file versions: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()

    @staticmethod
    def display_devices(devices_data: dict, verbose=False) -> None:
        """
        Displays devices information from the Nextcloud security page.
        Shows information about each device/session including name, type, and last activity time.
        
        Args:
            devices_data: Dictionary containing parsed device information and metadata
            verbose: If True, displays detailed information about each device
        """
        try:
            # Print header
            print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} Nextcloud Devices & Sessions {Style.RESET_ALL}\n")
            
            # Display metadata information
            print(f"{Fore.CYAN}{Style.BRIGHT}=== Information ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Devices:  {Fore.WHITE}{devices_data.get('count', 0)}")
            
            if verbose:
                print(f"{Fore.GREEN}Source URL:     {Fore.WHITE}{devices_data.get('url', 'N/A')}")
                print(f"{Fore.GREEN}Timestamp:      {Fore.WHITE}{devices_data.get('timestamp', 'N/A')}")
            
            # Display error message if present
            if 'error' in devices_data:
                print(f"\n{Fore.RED}{Style.BRIGHT}ERROR: {devices_data['error']}{Style.RESET_ALL}")
                return
            
            # Get devices list
            devices = devices_data.get('devices', [])
            
            if not devices:
                print(f"\n{Fore.YELLOW}No devices or sessions found.{Style.RESET_ALL}")
                return
                
            # Display devices information
            print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Devices & Sessions ({len(devices)}) ==={Style.RESET_ALL}")
            
            # Table header for compact view
            if not verbose:
                print(f"{Fore.BLUE}{'ID':<10} {'Type':<10} {'Last Activity':<20} {'Name':<30}{Style.RESET_ALL}")
                print(f"{Fore.BLUE}{'─' * 70}{Style.RESET_ALL}")
            
            for i, device in enumerate(devices, 1):
                # Get the device information
                device_id = device.get('id', 'N/A')
                device_type = device.get('type', 'unknown')
                device_name = device.get('name', 'Unknown Device')
                last_activity = device.get('last_activity', 'N/A')
                is_current = device.get('is_current_session', False)
                
                # Determine device type indicator
                type_indicator = ""
                if device_type == 'browser':
                    type_indicator = "[BROWSER]"
                elif device_type == 'mobile':
                    type_indicator = "[MOBILE]"
                elif device_type == 'desktop':
                    type_indicator = "[DESKTOP]"
                elif device_type == 'app':
                    type_indicator = "[APP]"
                else:
                    type_indicator = "[UNKNOWN]"
                
                # Current session indicator
                current_indicator = "*" if is_current else " "
                
                # Handle different display modes (verbose vs compact)
                if verbose:
                    # Determine if this is the current session text
                    current_session = ""
                    if is_current:
                        current_session = f"{Fore.GREEN}[Current Session]{Style.RESET_ALL} "
                    
                    # Display device header with name, type and ID
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}[{i}] {Fore.WHITE}{type_indicator} {device_name}{Style.RESET_ALL} {current_session}")
                    print(f"{Fore.BLUE}{'─' * 50}{Style.RESET_ALL}")
                    
                    # Display detailed device information
                    print(f"{Fore.GREEN}Device ID:      {Fore.WHITE}{device_id}")
                    print(f"{Fore.GREEN}Type:           {Fore.WHITE}{device_type.capitalize()}")
                    
                    if 'device_os' in device:
                        print(f"{Fore.GREEN}OS:             {Fore.WHITE}{device.get('device_os', 'N/A')}")
                        
                    print(f"{Fore.GREEN}Last Activity:  {Fore.WHITE}{last_activity}")
                    
                    # Show if device can be revoked and deleted
                    can_delete = device.get('can_delete', False)
                    delete_status = f"{Fore.GREEN}Yes" if can_delete else f"{Fore.RED}No"
                    print(f"{Fore.GREEN}Can Delete:     {delete_status}{Style.RESET_ALL}")
                    
                    # Show if filesystem access is enabled
                    fs_access = device.get('has_filesystem_access', False)
                    fs_status = f"{Fore.GREEN}Yes" if fs_access else f"{Fore.RED}No"
                    print(f"{Fore.GREEN}File Access:    {fs_status}{Style.RESET_ALL}")
                else:
                    # Compact row with important information
                    name_display = device_name[:28] + ".." if len(device_name) > 30 else device_name
                    type_short = device_type[:8].upper()
                    current_highlight = f"{Fore.GREEN}" if is_current else ""
                    print(f"{current_highlight}{device_id:<10} {type_short:<10} {last_activity:<20} {name_display}{Style.RESET_ALL}")
            
            # Add help info for revocation
            print(f"\n{Fore.YELLOW}Note: To revoke a device, use the 'revoke-device' action with --device-id parameter.{Style.RESET_ALL}")
            if not verbose:
                print(f"{Fore.YELLOW}Use --verbose for detailed information about each device.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Use --output-json to save the complete data for further analysis.{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying devices information: {str(e)}{Style.RESET_ALL}")