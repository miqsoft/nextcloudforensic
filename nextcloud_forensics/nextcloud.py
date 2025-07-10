#!/usr/bin/env python3
import argparse
import sys
import os
import json
from datetime import datetime
from .client import NextcloudClient, NextCloudWebClient
from .utils import NextcloudUtils
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description='Nextcloud Forensics Tool')
    parser.add_argument('--url', required=True, help='Nextcloud server URL')
    parser.add_argument('--username', required=True, help='Nextcloud username')
    parser.add_argument('--password', required=True, help='Nextcloud app password')
    parser.add_argument('--action', choices=['user-info', 'server-capabilities', 'trash-bin', 'list-files', 'file-activity', 'file-id-to-path', 'download-file', 'shares', 'list-users', 'search-user', 'revoke-app-password', 'file-versions', 'list-devices', 'revoke-device', 'dump'], default='user-info',
                      help='Action to perform (default: user-info)')
    parser.add_argument('--output-json', help='Save raw JSON output to specified file')
    parser.add_argument('--path', default='', help='Path to query (for list-files action, default: root directory)')
    parser.add_argument('--recursive', action='store_true', help='Query files recursively (for list-files action)')
    parser.add_argument('--file-id', help='File ID to query (required for file-activity, file-id-to-path, and download-file actions). Can be formatted as "fileid@timestamp" for versioned files')
    parser.add_argument('--limit', type=int, default=200, help='Maximum number of activities to fetch (for file-activity action, default: 200)')
    parser.add_argument('--download-path', help='Path where to save the downloaded file (for download-file action, optional)')
    parser.add_argument('--user-password', help='User password for web interface (required for list-devices action)')
    parser.add_argument('--session-file', help='Path to session file for web authentication (optional for list-devices action)')
    parser.add_argument('--search-term', help='Search term for user search')
    parser.add_argument('--device-id', help='Device ID for revoke-device action')
    parser.add_argument('--include-deleted', action='store_true', help='Include deleted files in dump action')
    parser.add_argument('--dump-dir', help='Destination directory for dump action (default: current working directory)')
    parser.add_argument('--proxy', help='Optional proxy server in the format "http://ip:port" or "https://ip:port"')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates (default: False)')
    parser.add_argument('--show-ssl-warnings', action='store_true', help='Show SSL verification warnings (default: False)')
    parser.add_argument('--verbose', action='store_true', help='Show verbose output with more details')
    parser.add_argument('--log-file', help='Path to save detailed API request logs')    
    args = parser.parse_args()
    
    # Re-enable SSL warnings if requested
    if args.show_ssl_warnings:
        import warnings
        warnings.filterwarnings('default', message='Unverified HTTPS request')
    
    try:
        # Initialize the client with proxy support, SSL verification settings, and logging
        client = NextcloudClient(
            base_url=args.url, 
            username=args.username, 
            app_password=args.password, 
            proxy=args.proxy, 
            verify_ssl=args.verify_ssl,
            log_file=args.log_file
        )
        
        # Execute the requested action
        if args.action == 'user-info':
            user_data = client.get_user()
            
            # Save raw JSON if requested
            if args.output_json:
                NextcloudUtils.save_json_to_file(user_data, args.output_json)
            
            # Display formatted user info
            NextcloudUtils.display_user_info(user_data)
            
        elif args.action == 'server-capabilities':
            capabilities_data = client.get_capabilities()
            
            # Save raw JSON if requested
            if args.output_json:
                NextcloudUtils.save_json_to_file(capabilities_data, args.output_json)
            
            # Display formatted capabilities info
            NextcloudUtils.display_capabilities(capabilities_data)
            
        elif args.action == 'trash-bin':
            # Get trash bin contents
            trash_items = client.get_trashbin()
            
            # Save raw JSON if requested
            if args.output_json:
                # Convert list to dict for consistent output format
                trash_data = {'items': trash_items}
                NextcloudUtils.save_json_to_file(trash_data, args.output_json)
            
            # Display formatted trash bin info
            NextcloudUtils.display_trashbin(trash_items)
            
        elif args.action == 'list-files':
            # Get files from the specified path
            files = client.get_files(path=args.path, recursive=args.recursive)
            
            # Save raw JSON if requested
            if args.output_json:
                # Convert list to dict for consistent output format
                file_data = {'items': files}
                NextcloudUtils.save_json_to_file(file_data, args.output_json)
            
            # Display formatted file listing
            NextcloudUtils.display_files(files, recursive=args.recursive)
            
        elif args.action == 'file-activity':
            # Check if file ID is provided
            if not args.file_id:
                print("Error: --file-id is required for file-activity action")
                sys.exit(1)
                
            # Get file activity data
            activity_data = client.get_file_activity(file_id=args.file_id, limit=args.limit)
            
            # Save raw JSON if requested
            if args.output_json:
                NextcloudUtils.save_json_to_file(activity_data, args.output_json)
            
            # Display formatted file activity
            NextcloudUtils.display_file_activity(activity_data)
            
        elif args.action == 'file-id-to-path':
            # Check if file ID is provided
            if not args.file_id:
                print("Error: --file-id is required for file-id-to-path action")
                sys.exit(1)
                
            # Get path from file ID
            try:
                file_path = client.get_path_by_file_id(file_id=args.file_id)
                
                # Save raw JSON if requested
                if args.output_json:
                    path_data = {'file_id': args.file_id, 'path': file_path}
                    NextcloudUtils.save_json_to_file(path_data, args.output_json)
                
                # Display the path
                print(f"File ID: {args.file_id}")
                print(f"Path: {file_path}")
                
            except ValueError as e:
                print(f"Error: {str(e)}")
                sys.exit(1)
        
        elif args.action == 'download-file':
            # Check if file ID is provided
            if not args.file_id:
                print("Error: --file-id is required for download-file action")
                sys.exit(1)
            
            # Parse the file ID to handle the "fileid@timestamp" format
            file_id = args.file_id
            version_timestamp = None
            
            # Check if the file ID includes a timestamp format (fileid@timestamp)
            if '@' in args.file_id:
                import re
                match = re.match(r'(\d+)@(\d+)', args.file_id)
                if match:
                    file_id = match.group(1)
                    version_timestamp = match.group(2)
                    print(f"{Fore.CYAN}Detected versioned file ID format: File ID {file_id}, Version timestamp {version_timestamp}{Style.RESET_ALL}")
            
            # Download the file
            try:
                saved_path = client.download_file_by_id(
                    file_id=file_id, 
                    download_path=args.download_path,
                    version_timestamp=version_timestamp
                )
                
                if version_timestamp:
                    print(f"File version {version_timestamp} of file with ID {file_id} has been downloaded to {saved_path}")
                else:
                    print(f"File with ID {file_id} has been downloaded to {saved_path}")
                    
            except ValueError as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
        
        elif args.action == 'shares':
            # Get shares data
            shares_data = client.get_shares()
            
            # Save raw JSON if requested
            if args.output_json:
                NextcloudUtils.save_json_to_file(shares_data, args.output_json)
            
            # Display formatted shares info
            NextcloudUtils.display_shares(shares_data)
        
        elif args.action == 'list-users':
            # Get list of users
            users_data = client.get_all_users()

            # Fetch detailed information for each user
            detailed_users_data = {}
            for username in users_data.get('ocs', {}).get('data', {}).get('users', []):
                try:
                    detailed_users_data[username] = client.search_user_details(search_term=username)
                except Exception as e:
                    print(f"Error fetching details for user {username}: {str(e)}")

            # Save raw JSON if requested
            if args.output_json:
                NextcloudUtils.save_json_to_file(detailed_users_data, args.output_json)

            # Display formatted user list with details
            NextcloudUtils.display_all_users(users_data, detailed_users_data)
        
        elif args.action == 'search-user':
            # Check if search term is provided
            if not args.search_term:
                print("Error: --search-term is required for search-user action")
                sys.exit(1)
            
            # Search for users
            search_results = client.search_user_details(search_term=args.search_term)
            
            # Save raw JSON if requested
            if args.output_json:
                NextcloudUtils.save_json_to_file(search_results, args.output_json)
            
            # Display search results
            print("Search results:")
            print(search_results)
        
        elif args.action == 'revoke-app-password':
            print(f"You are about to attempt revoking an app password for user '{args.username}'.")
            
            # Ask which password to revoke
            prompt = f"Revoke the app password provided via --password ('{args.password[:4]}...{args.password[-4:]}')? [Y/n] or enter the password to revoke: "
            user_input = input(prompt).strip()

            password_to_revoke = args.password # Default to the one provided
            
            if user_input.lower() == 'n':
                print("Operation cancelled.")
                sys.exit(0)
            elif user_input and user_input.lower() != 'y':
                password_to_revoke = user_input # Use the entered password

            # Display warning
            print(f"{Fore.RED}{Style.BRIGHT}WARNING: This action is irreversible!{Style.RESET_ALL}")
            print(f"You are about to revoke the app password: '{password_to_revoke[:4]}...{password_to_revoke[-4:]}'")
            confirm = input("Are you sure you want to proceed? [y/N]: ").strip().lower()

            if confirm != 'y':
                print("Revocation cancelled.")
                sys.exit(0)

            # Perform the revocation
            try:
                print("Sending revocation request...")
                client.revoke_app_password(password_to_revoke)
                print(f"{Fore.GREEN}App password successfully revoked.{Style.RESET_ALL}")

                # Verify revocation
                print("Verifying revocation...")
                is_revoked = client.verify_app_password_revoked(password_to_revoke)
                if is_revoked:
                    print(f"{Fore.GREEN}Verification successful: The app password is no longer valid.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}Verification inconclusive: The app password might still be valid or another error occurred.{Style.RESET_ALL}")

            except Exception as revoke_error:
                print(f"{Fore.RED}Error revoking app password: {str(revoke_error)}{Style.RESET_ALL}")
                sys.exit(1)
        
        elif args.action == 'file-versions':
            # Check if file ID is provided
            if not args.file_id:
                print("Error: --file-id is required for file-versions action")
                sys.exit(1)
            
            # Get file versions
            try:
                versions_data = client.get_file_versions(file_id=args.file_id)
                
                # Save raw JSON if requested
                if args.output_json:
                    NextcloudUtils.save_json_to_file(versions_data, args.output_json)
                
                # Display file versions
                NextcloudUtils.display_file_versions(versions_data)
            
            except Exception as e:
                print(f"Error: {str(e)}")
                sys.exit(1)
        
        elif args.action == 'list-devices':
            # Check if user password is provided
            if not args.user_password:
                print(f"{Fore.RED}Error: --user-password is required for list-devices action{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Note: This action requires your full Nextcloud user password, not an app password{Style.RESET_ALL}")
                sys.exit(1)
                
            try:
                # Initialize the web client
                web_client = NextCloudWebClient(
                    base_url=args.url, 
                    username=args.username, 
                    user_password=args.user_password, 
                    session_file=args.session_file,
                    proxy=args.proxy,
                    verify_ssl=args.verify_ssl,
                    log_file=args.log_file
                )
                
                # Get devices data
                devices_data = web_client.list_devices()
                
                # Save raw data if requested
                if args.output_json:
                    NextcloudUtils.save_json_to_file(devices_data, args.output_json)
                
                # Display devices info
                NextcloudUtils.display_devices(devices_data, verbose=args.verbose)
                
            except Exception as e:
                print(f"{Fore.RED}Error listing devices: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
                
        elif args.action == 'revoke-device':
            # Check required parameters
            if not args.user_password:
                print(f"{Fore.RED}Error: --user-password is required for revoke-device action{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Note: This action requires your full Nextcloud user password, not an app password{Style.RESET_ALL}")
                sys.exit(1)
                
            if not args.device_id:
                print(f"{Fore.RED}Error: --device-id is required for revoke-device action{Style.RESET_ALL}")
                sys.exit(1)
                
            try:
                # Initialize the web client
                web_client = NextCloudWebClient(
                    base_url=args.url, 
                    username=args.username, 
                    user_password=args.user_password, 
                    session_file=args.session_file,
                    proxy=args.proxy,
                    verify_ssl=args.verify_ssl,
                    log_file=args.log_file
                )
                
                # Attempt to revoke the device
                print(f"{Fore.YELLOW}Attempting to revoke device with ID: {args.device_id}{Style.RESET_ALL}")
                result = web_client.revoke_device(args.device_id)
                
                if result:
                    print(f"{Fore.GREEN}Device with ID {args.device_id} was successfully revoked.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Failed to revoke device with ID {args.device_id}.{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}Error revoking device: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
                
        elif args.action == 'dump':
            try:
                # Set default destination directory to current working directory if not specified
                dump_dir = args.dump_dir if args.dump_dir else os.getcwd()
                
                # Get timestamp for the acquisition
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                
                # Create the main dump directory
                dump_folder_name = f"nextcloud_dump_{timestamp}"
                dump_folder_path = os.path.join(dump_dir, dump_folder_name)
                os.makedirs(dump_folder_path, exist_ok=True)
                
                # Create meta directory for acquisition info
                meta_dir = os.path.join(dump_folder_path, "_metadata")
                os.makedirs(meta_dir, exist_ok=True)
                
                # Create files directory for file content
                files_dir = os.path.join(dump_folder_path, "files")
                os.makedirs(files_dir, exist_ok=True)
                
                # Save acquisition metadata
                acquisition_info = {
                    "timestamp": timestamp,
                    "nextcloud_url": args.url,
                    "username": args.username,
                    "acquisition_date": datetime.now().isoformat(),
                    "include_deleted": args.include_deleted
                }
                
                # Save acquisition info to meta directory
                with open(os.path.join(meta_dir, "acquisition_info.json"), 'w') as f:
                    json.dump(acquisition_info, f, indent=4)
                
                print(f"{Fore.CYAN}Starting Nextcloud dump to {dump_folder_path}{Style.RESET_ALL}")
                
                # Get user information
                print(f"{Fore.BLUE}[1/5] Gathering user information...{Style.RESET_ALL}")
                user_data = client.get_user()
                NextcloudUtils.save_json_to_file(user_data, os.path.join(meta_dir, "user_info.json"))
                
                # Get server capabilities
                print(f"{Fore.BLUE}[2/5] Gathering server capabilities...{Style.RESET_ALL}")
                capabilities_data = client.get_capabilities()
                NextcloudUtils.save_json_to_file(capabilities_data, os.path.join(meta_dir, "server_capabilities.json"))
                
                # Get file listing first (recursive)
                print(f"{Fore.BLUE}[3/5] Building file hierarchy...{Style.RESET_ALL}")
                files = client.get_files(path='', recursive=True)
                NextcloudUtils.save_json_to_file({'items': files}, os.path.join(meta_dir, "file_listing.json"))
                
                # Get trash bin if include deleted is specified
                trash_items = []
                if args.include_deleted:
                    print(f"{Fore.BLUE}[4/5] Retrieving deleted files from trash bin...{Style.RESET_ALL}")
                    trash_items = client.get_trashbin()
                    NextcloudUtils.save_json_to_file({'items': trash_items}, os.path.join(meta_dir, "trash_bin.json"))
                else:
                    print(f"{Fore.BLUE}[4/5] Skipping deleted files (use --include-deleted to include them){Style.RESET_ALL}")
                    
                # Download all the files
                print(f"{Fore.BLUE}[5/5] Downloading files...{Style.RESET_ALL}")
                total_files = len(files)
                processed_files = 0
                downloaded_files = 0
                skipped_files = 0
                errors = 0
                
                for file_item in files:
                    processed_files += 1
                    file_id = file_item.get('id') or file_item.get('fileid')
                    
                    # Skip if it's a directory
                    if file_item.get('is_collection'):
                        # Create the directory structure
                        rel_path = file_item.get('path', '')
                        if rel_path.startswith('/'):
                            rel_path = rel_path[1:]  # Remove leading slash
                            
                        dir_path = os.path.join(files_dir, rel_path)
                        os.makedirs(dir_path, exist_ok=True)
                        skipped_files += 1
                        continue
                        
                    if not file_id:
                        print(f"{Fore.YELLOW}Warning: No file ID found for {file_item.get('path')}, skipping{Style.RESET_ALL}")
                        skipped_files += 1
                        continue
                    
                    # Get file path
                    file_path = file_item.get('path', '')
                    if file_path.startswith('/'):
                        file_path = file_path[1:]  # Remove leading slash
                        
                    # Create directory structure
                    dir_name = os.path.dirname(file_path)
                    local_dir_path = os.path.join(files_dir, dir_name)
                    os.makedirs(local_dir_path, exist_ok=True)
                    
                    # Prepare local path for file
                    local_file_path = os.path.join(files_dir, file_path)
                    
                    # Print progress
                    progress = (processed_files / total_files) * 100
                    print(f"\r{Fore.GREEN}Progress: {processed_files}/{total_files} ({progress:.1f}%) - Downloading: {file_path}{' ' * 20}", end='')
                    
                    try:
                        # Download file
                        client.download_file_by_id(file_id=str(file_id), download_path=local_file_path)
                        downloaded_files += 1
                        
                    except Exception as e:
                        print(f"\n{Fore.RED}Error downloading {file_path}: {str(e)}{Style.RESET_ALL}")
                        errors += 1
                
                # Download deleted files if requested
                if args.include_deleted and trash_items:
                    print(f"\n{Fore.BLUE}Downloading deleted files...{Style.RESET_ALL}")
                    deleted_files_dir = os.path.join(dump_folder_path, "deleted_files")
                    os.makedirs(deleted_files_dir, exist_ok=True)
                    
                    total_deleted = len(trash_items)
                    processed_deleted = 0
                    downloaded_deleted = 0
                    error_deleted = 0
                    
                    for trash_item in trash_items:
                        processed_deleted += 1
                        file_id = trash_item.get('id') or trash_item.get('fileid')
                        original_location = trash_item.get('original_location', '')
                        filename = trash_item.get('filename', f"deleted_file_{file_id}")
                        
                        if not file_id:
                            print(f"{Fore.YELLOW}Warning: No file ID found for deleted file {filename}, skipping{Style.RESET_ALL}")
                            continue
                        
                        # Create directory structure based on original location
                        if original_location:
                            dir_name = os.path.dirname(original_location)
                            local_dir_path = os.path.join(deleted_files_dir, dir_name)
                            os.makedirs(local_dir_path, exist_ok=True)
                            local_file_path = os.path.join(deleted_files_dir, original_location)
                        else:
                            local_file_path = os.path.join(deleted_files_dir, filename)
                        
                        # Print progress
                        progress = (processed_deleted / total_deleted) * 100
                        print(f"\r{Fore.GREEN}Progress: {processed_deleted}/{total_deleted} ({progress:.1f}%) - Downloading deleted: {filename}{' ' * 20}", end='')
                        
                        try:
                            # Download the deleted file
                            client.download_file_by_id(file_id=str(file_id), download_path=local_file_path)
                            downloaded_deleted += 1
                            
                        except Exception as e:
                            print(f"\n{Fore.RED}Error downloading deleted file {filename}: {str(e)}{Style.RESET_ALL}")
                            error_deleted += 1
                
                print("\n")
                print(f"{Fore.GREEN}Nextcloud dump completed successfully!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Summary:{Style.RESET_ALL}")
                print(f"  • Dump location: {dump_folder_path}")
                print(f"  • Total files processed: {total_files}")
                print(f"  • Files downloaded: {downloaded_files}")
                print(f"  • Directories created: {skipped_files}")
                print(f"  • Download errors: {errors}")
                
                if args.include_deleted:
                    print(f"  • Deleted files processed: {total_deleted}")
                    print(f"  • Deleted files downloaded: {downloaded_deleted}")
                    print(f"  • Deleted files errors: {error_deleted}")
                
                # Save the summary to the metadata directory
                summary = {
                    "dump_location": dump_folder_path,
                    "total_files_processed": total_files,
                    "files_downloaded": downloaded_files,
                    "directories_created": skipped_files,
                    "download_errors": errors
                }
                
                if args.include_deleted:
                    summary.update({
                        "deleted_files_processed": total_deleted,
                        "deleted_files_downloaded": downloaded_deleted,
                        "deleted_files_errors": error_deleted
                    })
                
                NextcloudUtils.save_json_to_file(summary, os.path.join(meta_dir, "summary.json"))
                
            except Exception as e:
                print(f"{Fore.RED}Error performing dump: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
        
        else:
            print(f"Unknown action: {args.action}")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()