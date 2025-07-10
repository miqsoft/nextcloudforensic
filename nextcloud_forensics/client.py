import base64
import requests
import xml.etree.ElementTree as ET
import re
import json
import os
import warnings
from datetime import datetime
from .utils import NextcloudLogger

# Disable insecure request warnings when verify=False is used
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class NextcloudClient:
    def __init__(self, base_url: str, username: str, app_password: str, proxy: str = None, verify_ssl: bool = True, log_file: str = None):
        """
        Initializes the NextcloudClient with base URL, username, and app password.
        Sets up a session with default headers for OCS API requests.
        
        Args:
            base_url: The base URL of the Nextcloud instance
            username: The username to authenticate with
            app_password: The app password for authentication
            proxy: Optional proxy server in the format "http://ip:port" or "https://ip:port"
            verify_ssl: Whether to verify SSL certificates (default: True)
            log_file: Optional path to log all API requests and responses to a file
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = app_password  # Store password for web login
        self.session = requests.Session()
        
        # Initialize the logger
        self.logger = NextcloudLogger.get_instance(log_file)
        self.logger.info(f"Initializing NextcloudClient for {username}@{base_url}")
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy,
            }
            self.logger.info(f"Using proxy: {proxy}")
        
        # Set SSL verification
        self.session.verify = verify_ssl
        if not verify_ssl:
            self.logger.warning("SSL certificate verification is disabled - this is insecure and should only be used for testing")
        
        # Prepare Basic auth header
        credentials = f"{username}:{app_password}"
        b64_credentials = base64.b64encode(credentials.encode()).decode()
        self.session.headers.update({
            'OCS-APIRequest': 'true',
            'Accept': 'application/json',
            'Authorization': f'Basic {b64_credentials}',
            'Content-Type': 'application/x-www-form-urlencoded',
        })
        
        # Monkey patch the session to log all requests
        original_request = self.session.request
        
        def logging_request(method, url, **kwargs):
            self.logger.log_request(method, url, **kwargs)
            response = original_request(method, url, **kwargs)
            self.logger.log_response(response)
            return response
            
        self.session.request = logging_request

    def get_user(self) -> dict:
        """
        Fetches and returns user information from the Nextcloud server.
        """
        url = f"{self.base_url}/ocs/v2.php/cloud/user"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
        
    def get_capabilities(self) -> dict:
        """
        Fetches and returns server capabilities from the Nextcloud server.
        """
        url = f"{self.base_url}/ocs/v1.php/cloud/capabilities"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
        
    def get_trashbin(self) -> list:
        """
        Fetches and returns the trash bin contents from the Nextcloud server.
        
        Returns:
            A list of trash bin items with their properties.
        """
        # Set headers for WebDAV request
        webdav_headers = {
            'Content-Type': 'application/xml',
            'Depth': '1',
        }
        
        # Create PROPFIND XML request
        propfind_xml = """<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <d:prop>
    <d:displayname />
    <d:getcontenttype />
    <d:resourcetype />
    <oc:id/>
    <oc:fileid/>
    <oc:size/>
    <nc:has-preview/>
    <nc:trashbin-filename/>
    <nc:trashbin-original-location/>
    <nc:trashbin-deletion-time/>
  </d:prop>
</d:propfind>"""
        
        # Make request to trashbin endpoint
        url = f"{self.base_url}/remote.php/dav/trashbin/{self.username}/trash/"
        response = self.session.request('PROPFIND', url, headers=webdav_headers, data=propfind_xml)
        response.raise_for_status()
        
        # Parse XML response
        root = ET.fromstring(response.content)
        
        # Extract item information
        items = []
        # Skip first response which is the trash folder itself
        for response_tag in root.findall('.//{DAV:}response')[1:]:
            item = {}
            
            # Get the href (path)
            href = response_tag.find('.//{DAV:}href')
            if href is not None:
                item['href'] = href.text
                
            # Get all properties with 200 OK status
            propstat = response_tag.find('.//{DAV:}propstat[{DAV:}status="HTTP/1.1 200 OK"]')
            if propstat is not None:
                prop = propstat.find('.//{DAV:}prop')
                
                # Extract basic properties
                displayname = prop.find('.//{DAV:}displayname')
                if displayname is not None and displayname.text:
                    item['displayname'] = displayname.text
                
                contenttype = prop.find('.//{DAV:}getcontenttype')
                if contenttype is not None and contenttype.text:
                    item['contenttype'] = contenttype.text
                
                # Check if it's a collection (folder)
                resourcetype = prop.find('.//{DAV:}resourcetype')
                if resourcetype is not None and resourcetype.find('.//{DAV:}collection') is not None:
                    item['is_collection'] = True
                else:
                    item['is_collection'] = False
                
                # Extract Nextcloud specific properties
                fileid = prop.find('.//{http://owncloud.org/ns}fileid')
                if fileid is not None and fileid.text:
                    item['fileid'] = fileid.text
                
                size = prop.find('.//{http://owncloud.org/ns}size')
                if size is not None and size.text:
                    item['size'] = int(size.text)
                
                has_preview = prop.find('.//{http://nextcloud.org/ns}has-preview')
                if has_preview is not None and has_preview.text:
                    item['has_preview'] = True if has_preview.text == "1" else False
                
                # Trashbin specific properties
                original_name = prop.find('.//{http://nextcloud.org/ns}trashbin-filename')
                if original_name is not None and original_name.text:
                    item['original_filename'] = original_name.text
                
                original_location = prop.find('.//{http://nextcloud.org/ns}trashbin-original-location')
                if original_location is not None and original_location.text:
                    item['original_location'] = original_location.text
                
                deletion_time = prop.find('.//{http://nextcloud.org/ns}trashbin-deletion-time')
                if deletion_time is not None and deletion_time.text:
                    item['deletion_time'] = int(deletion_time.text)
            
            items.append(item)
            
        return items

    def get_files(self, path: str = '', recursive: bool = False) -> list:
        """
        Fetches and returns files and directories from the Nextcloud server.
        
        Args:
            path: The path to query (default: root directory)
            recursive: Whether to fetch files recursively (default: False)
        
        Returns:
            A list of file/directory items with their properties.
        """
        # For recursive mode, we'll need to handle the search differently
        if recursive:
            return self._get_files_recursive(path)
        else:
            return self._get_files_single(path)

    def _get_files_single(self, path: str = '') -> list:
        """
        Helper method to fetch files from a single directory.
        """
        # Set headers for WebDAV request
        webdav_headers = {
            'Content-Type': 'application/xml',
            'Depth': '10',  # Only direct children
        }
        
        # Create PROPFIND XML request for file properties
        propfind_xml = """<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <d:prop>
    <d:displayname />
    <d:getlastmodified />
    <d:getetag />
    <d:resourcetype />
    <d:getcontenttype />
    <d:getcontentlength />
    <oc:permissions />
    <oc:id />
    <oc:fileid />
    <oc:size />
    <oc:favorite />
    <oc:share-types />
    <oc:owner-id />
    <oc:owner-display-name />
    <nc:creation_time />
    <nc:upload_time />
    <nc:has-preview />
  </d:prop>
</d:propfind>"""
        
        # Format the URL - handle both empty path and non-empty path
        formatted_path = path.strip('/')
        url_path = f"remote.php/dav/files/{self.username}"
        
        # If there's a path, append it directly to the URL without additional slashes
        if formatted_path:
            url = f"{self.base_url}/{url_path}/{formatted_path}"
        else:
            url = f"{self.base_url}/{url_path}"
            
        # Make request to files endpoint
        response = self.session.request('PROPFIND', url, headers=webdav_headers, data=propfind_xml)
        response.raise_for_status()
        
        # Parse XML response
        return self._parse_files_response(response.content)

    def _get_files_recursive(self, path: str = '') -> list:
        """
        Helper method to recursively fetch all files starting from a path.
        This method will handle directory traversal manually rather than relying on 'infinity' depth.
        """
        # Get initial set of files
        all_items = self._get_files_single(path)
        
        # Find directories to traverse
        directories = [item for item in all_items[1:] if item.get('is_collection', False)]  # Skip the first item which is the directory itself
        
        # Recursively get files for each directory
        for directory in directories:
            # Extract the path from the item, removing leading slash to avoid double slashes
            dir_path = directory.get('path', '').lstrip('/')
            # Get files for this subdirectory
            sub_items = self._get_files_recursive(dir_path)
            # Add all items except the directory itself (which is the first item)
            all_items.extend(sub_items[1:])
            
        return all_items

    def _parse_files_response(self, xml_content) -> list:
        """
        Helper method to parse the XML response from a PROPFIND request.
        """
        # Parse XML response
        root = ET.fromstring(xml_content)
        
        # Extract item information
        items = []
        
        for response_tag in root.findall('.//{DAV:}response'):
            item = {}
            
            # Get the href (path)
            href = response_tag.find('.//{DAV:}href')
            if href is not None:
                item['href'] = href.text
                
                # Extract the relative path from the href
                path_parts = href.text.split('/')
                if 'remote.php/dav/files' in href.text:
                    # Find the index after username
                    try:
                        username_idx = path_parts.index(self.username)
                        rel_path = '/'.join(path_parts[username_idx + 1:])
                        item['path'] = '/' + rel_path if rel_path else '/'
                    except ValueError:
                        item['path'] = href.text
                else:
                    item['path'] = href.text
            
            # Get all properties with 200 OK status
            propstat = response_tag.find('.//{DAV:}propstat[{DAV:}status="HTTP/1.1 200 OK"]')
            if propstat is not None:
                prop = propstat.find('.//{DAV:}prop')
                
                # Extract basic properties
                displayname = prop.find('.//{DAV:}displayname')
                if displayname is not None and displayname.text:
                    item['displayname'] = displayname.text
                
                lastmodified = prop.find('.//{DAV:}getlastmodified')
                if lastmodified is not None and lastmodified.text:
                    item['lastmodified'] = lastmodified.text
                
                etag = prop.find('.//{DAV:}getetag')
                if etag is not None and etag.text:
                    item['etag'] = etag.text.strip('"')
                
                contenttype = prop.find('.//{DAV:}getcontenttype')
                if contenttype is not None and contenttype.text:
                    item['contenttype'] = contenttype.text
                
                contentlength = prop.find('.//{DAV:}getcontentlength')
                if contentlength is not None and contentlength.text:
                    item['contentlength'] = int(contentlength.text)
                
                # Check if it's a collection (folder)
                resourcetype = prop.find('.//{DAV:}resourcetype')
                if resourcetype is not None and resourcetype.find('.//{DAV:}collection') is not None:
                    item['is_collection'] = True
                else:
                    item['is_collection'] = False
                
                # Extract Nextcloud specific properties
                permissions = prop.find('.//{http://owncloud.org/ns}permissions')
                if permissions is not None and permissions.text:
                    item['permissions'] = permissions.text
                
                fileid = prop.find('.//{http://owncloud.org/ns}fileid')
                if fileid is not None and fileid.text:
                    item['fileid'] = fileid.text
                
                size = prop.find('.//{http://owncloud.org/ns}size')
                if size is not None and size.text:
                    item['size'] = int(size.text)
                
                favorite = prop.find('.//{http://owncloud.org/ns}favorite')
                if favorite is not None and favorite.text:
                    item['favorite'] = favorite.text == "1"
                
                owner_id = prop.find('.//{http://owncloud.org/ns}owner-id')
                if owner_id is not None and owner_id.text:
                    item['owner_id'] = owner_id.text
                
                owner_name = prop.find('.//{http://owncloud.org/ns}owner-display-name')
                if owner_name is not None and owner_name.text:
                    item['owner_name'] = owner_name.text
                
                creation_time = prop.find('.//{http://nextcloud.org/ns}creation_time')
                if creation_time is not None and creation_time.text:
                    item['creation_time'] = int(creation_time.text)
                
                upload_time = prop.find('.//{http://nextcloud.org/ns}upload_time')
                if upload_time is not None and upload_time.text:
                    item['upload_time'] = int(upload_time.text)
                
                has_preview = prop.find('.//{http://nextcloud.org/ns}has-preview')
                if has_preview is not None and has_preview.text:
                    item['has_preview'] = has_preview.text == "true"
            
            items.append(item)
            
        return items

    def get_file_activity(self, file_id: str, limit: int = 200) -> dict:
        """
        Fetches activity history for a specific file or directory from the Nextcloud server.
        
        Args:
            file_id: The file ID to query activity for
            limit: Maximum number of activities to fetch (default: 200)
            
        Returns:
            A dictionary containing the activity data for the specified file
        """
        url = f"{self.base_url}/ocs/v2.php/apps/activity/api/v2/activity/filter"
        
        params = {
            "format": "json",
            "object_id": file_id,
            "object_type": "files",
            "previews": "true",
            "since": "0",
            "limit": str(limit)
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
        
    def get_path_by_file_id(self, file_id: str) -> dict:
        """
        Converts a file ID to its path using WebDAV search request.
        First checks active files, and if not found, checks the trashbin.
        
        Args:
            file_id: The file ID to query for its path
            
        Returns:
            A dictionary containing the path and href of the file/directory, prefixed with '/trash/' if found in trashbin
        
        Raises:
            requests.exceptions.HTTPError: If the request fails
            ValueError: If the file was not found in both active files and trashbin
        """
        try:
            # First try to find the file in active files
            return self._get_path_by_file_id_active(file_id)
        except ValueError:
            # If not found in active files, check the trashbin
            try:
                trashbin_info = self._get_path_by_file_id_trashbin(file_id)
                trashbin_info['path'] = f"/trash{trashbin_info['path']}" if trashbin_info['path'] else None
                return trashbin_info
            except ValueError:
                # If still not found, raise the original error
                raise ValueError(f"Could not find path for file ID: {file_id} in either active files or trashbin")
            
    def _get_path_by_file_id_active(self, file_id: str) -> dict:
        """
        Converts a file ID to its path in active files using WebDAV search request.
        
        Args:
            file_id: The file ID to query for its path
            
        Returns:
            A dictionary containing the path and href of the file/directory
        
        Raises:
            requests.exceptions.HTTPError: If the request fails
            ValueError: If the file was not found
        """
        # Set headers for WebDAV request
        webdav_headers = {
            'Content-Type': 'text/xml',
        }
        
        # Create SEARCH XML request to find file by ID
        search_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<d:searchrequest xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:basicsearch>
    <d:select>
      <d:prop>
        <d:displayname />
        <d:getcontenttype />
        <d:resourcetype />
        <oc:fileid />
      </d:prop>
    </d:select>
    <d:from>
      <d:scope>
        <d:href>/remote.php/dav/files/{self.username}/</d:href>
        <d:depth>infinity</d:depth>
      </d:scope>
    </d:from>
    <d:where>
      <d:eq>
        <d:prop>
          <oc:fileid />
        </d:prop>
        <d:literal>{file_id}</d:literal>
      </d:eq>
    </d:where>
  </d:basicsearch>
</d:searchrequest>"""

        # Make search request to find the file
        url = f"{self.base_url}/remote.php/dav"
        
        try:
            response = self.session.request('SEARCH', url, headers=webdav_headers, data=search_xml)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.content)
            
            # Try to find the file in the response
            href = root.find('.//{DAV:}href')
            if href is not None:
                path_text = href.text
                
                # Extract the relative path from the href
                path_parts = path_text.split('/')
                if 'remote.php/dav/files' in path_text:
                    # Find the index after username
                    try:
                        username_idx = path_parts.index(self.username)
                        rel_path = '/'.join(path_parts[username_idx + 1:])
                        return {'path': '/' + rel_path if rel_path else '/', 'href': path_text}
                    except ValueError:
                        return {'path': path_text, 'href': path_text}
                else:
                    return {'path': path_text, 'href': path_text}
            
            # File not found or no path in response
            raise ValueError(f"Could not find path for file ID: {file_id} in active files")
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404 or e.response.status_code == 405:
                # If SEARCH is not supported, fall back to recursive listing method
                return self._get_path_by_file_id_fallback(file_id, search_in_trashbin=False)
            raise
            
    def _get_path_by_file_id_trashbin(self, file_id: str) -> dict:
        """
        Searches for a file by ID in the trashbin.
        
        Args:
            file_id: The file ID to search for in the trashbin
            
        Returns:
            A dictionary containing the path and href of the file/directory in the trashbin
            
        Raises:
            ValueError: If the file was not found in the trashbin
        """
        # Get all items from the trashbin
        trash_items = self.get_trashbin()
        
        # Search for the file with the given ID
        for item in trash_items:
            if item.get('fileid') == file_id:
                # Get the href and replace the trashbin path with the correct username
                href = item.get('href', '')
                trashbin_path = href.replace(f'/remote.php/dav/trashbin/{self.username}/trash', '')
                return {'path': trashbin_path, 'href': href}
                
        # File not found in trashbin
        raise ValueError(f"Could not find path for file ID: {file_id} in trashbin")
    
    def _get_path_by_file_id_fallback(self, file_id: str, search_in_trashbin: bool = True) -> dict:
        """
        Fallback method to find a file path by ID by recursively listing all files.
        
        Args:
            file_id: The file ID to search for
            search_in_trashbin: Whether to also search in the trashbin if not found in active files
            
        Returns:
            A dictionary containing the path and href of the file/directory
            
        Raises:
            ValueError: If the file was not found
        """
        # Get all files recursively from root
        all_files = self.get_files(path='', recursive=True)
        
        # Search for the file with the given ID
        for file in all_files:
            if file.get('fileid') == file_id:
                return {'path': file.get('path'), 'href': file.get('href')}
        
        # If not found in active files and search_in_trashbin is True, try trashbin
        if search_in_trashbin:
            try:
                trashbin_info = self._get_path_by_file_id_trashbin(file_id)
                trashbin_info['path'] = f"/trash{trashbin_info['path']}" if trashbin_info['path'] else None
                return trashbin_info
            except ValueError:
                pass
                
        # File not found
        raise ValueError(f"Could not find path for file ID: {file_id}")

    def download_file_by_id(self, file_id: str, download_path: str = None, version_timestamp: str = None) -> str:
        """
        Downloads a file by its file ID using a single GET request.
        
        Args:
            file_id: The file ID of the file to download
            download_path: Optional path where the file should be saved
                           If not specified, the file will be saved to the current working directory
                           with its original filename
            version_timestamp: Optional timestamp to download a specific version of the file
            
        Returns:
            The path where the file was saved
            
        Raises:
            ValueError: If the file was not found or if the specified version timestamp doesn't exist
            requests.exceptions.HTTPError: If the download request fails
            IOError: If there's an issue writing the downloaded file
        """
        import os

        # If version_timestamp is provided, use the version-specific endpoint
        if version_timestamp:
            # Construct the versioned file URL
            url = f"{self.base_url}/remote.php/dav/versions/{self.username}/versions/{file_id}/{version_timestamp}"
            
            # Get file metadata using the endpoint directly to check if version exists
            try:
                # Get metadata to validate the version exists and to get file info
                file_metadata = self.get_file_metadata_by_id(file_id, version_timestamp)
                filename = file_metadata.get('displayname', f"file_{file_id}_v{version_timestamp}")
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    raise ValueError(f"Version timestamp {version_timestamp} not found for file ID: {file_id}")
                raise
            except ValueError:
                raise ValueError(f"Version timestamp {version_timestamp} not found for file ID: {file_id}")
        else:
            # Get the file path and href from our helper method
            file_info = self.get_path_by_file_id(file_id)
            
            # Extract the relative path and complete server path (href)
            file_path = file_info['path']
            url = f"{self.base_url}{file_info['href']}"
            
            # Extract the filename from the path
            filename = os.path.basename(file_path)

        # Determine where to save the file
        if download_path:
            # If download_path is a directory, append the filename
            if os.path.isdir(download_path):
                save_path = os.path.join(download_path, filename)
            else:
                save_path = download_path
        else:
            # Save in current working directory with original filename
            save_path = os.path.join(os.getcwd(), filename)
            
        # Add version suffix to filename if it's a versioned download
        if version_timestamp and os.path.isdir(download_path or os.getcwd()):
            base_name, ext = os.path.splitext(save_path)
            save_path = f"{base_name}_v{version_timestamp}{ext}"
        
        # Download the file with a single GET request
        response = self.session.get(url, stream=True)
        response.raise_for_status()
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
        
        # Save the file
        with open(save_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    
        return save_path

    def revoke_app_password(self, password_to_revoke: str) -> None:
        """
        Revokes a specific app password for the current user.

        Args:
            password_to_revoke: The app password to be revoked.

        Raises:
            requests.exceptions.HTTPError: If the API request fails.
        """
        url = f"{self.base_url}/ocs/v2.php/core/apppassword"
        
        # Need to create a temporary session with the password to be revoked for auth
        temp_session = requests.Session()
        # Use the same proxy and SSL verification settings as the main session
        if hasattr(self.session, 'proxies') and self.session.proxies:
            temp_session.proxies = self.session.proxies
        temp_session.verify = self.session.verify
        
        credentials = f"{self.username}:{password_to_revoke}"
        b64_credentials = base64.b64encode(credentials.encode()).decode()
        temp_session.headers.update({
            'OCS-APIRequest': 'true',
            'Accept': 'application/json',
            'Authorization': f'Basic {b64_credentials}',
        })

        response = temp_session.delete(url)
        response.raise_for_status() # Will raise an exception for non-2xx status codes
        
        # Check OCS status code in the response if available
        try:
            ocs_data = response.json().get('ocs', {})
            meta = ocs_data.get('meta', {})
            if meta.get('statuscode') != 200:
                raise requests.exceptions.HTTPError(f"API Error: {meta.get('message', 'Unknown error')}", response=response)
        except (requests.exceptions.JSONDecodeError, AttributeError):
            # If response is not JSON or structure is unexpected, rely on HTTP status code
            pass

    def verify_app_password_revoked(self, revoked_password: str) -> bool:
        """
        Verifies if a specific app password has been successfully revoked by attempting
        a simple API call (get_user) with it.

        Args:
            revoked_password: The app password that should have been revoked.

        Returns:
            True if the password seems revoked (API call fails with 401), False otherwise.
        """
        temp_session = requests.Session()
        # Use the same proxy and SSL verification settings as the main session
        if hasattr(self.session, 'proxies') and self.session.proxies:
            temp_session.proxies = self.session.proxies
        temp_session.verify = self.session.verify
        
        credentials = f"{self.username}:{revoked_password}"
        b64_credentials = base64.b64encode(credentials.encode()).decode()
        temp_session.headers.update({
            'OCS-APIRequest': 'true',
            'Accept': 'application/json',
            'Authorization': f'Basic {b64_credentials}',
        })
        
        url = f"{self.base_url}/ocs/v2.php/cloud/user"
        
        try:
            response = temp_session.get(url)
            # If the request succeeds (2xx status), the password is still valid
            if response.ok:
                return False
            # If the request fails with 401 Unauthorized, the password is revoked
            elif response.status_code == 401:
                return True
            # Any other error means we can't be sure
            else:
                return False
        except requests.exceptions.RequestException:
            # Network errors etc. mean we can't verify
            return False

    def get_shares(self, reshares: bool = False, shared_with_me: bool = False, subfiles: bool = False) -> dict:
        """
        Fetches and returns shares information from the Nextcloud server.
        
        Args:
            reshares: Whether to include reshares (default: False)
            shared_with_me: Whether to include shares shared with the user (default: False)
            subfiles: Whether to include subfiles (default: False)
        
        Returns:
            A dictionary containing the shares data
        """
        url = f"{self.base_url}/ocs/v2.php/apps/files_sharing/api/v1/shares"
        
        params = {
            "reshares": str(reshares).lower(),
            "shared_with_me": str(shared_with_me).lower(),
            "subfiles": str(subfiles).lower()
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
        
    def get_all_users(self) -> dict:
        """
        Fetches and returns a list of all users from the Nextcloud server.
        This is an administrative API call and requires admin privileges.
        
        Returns:
            A dictionary containing the users data
        
        Raises:
            requests.exceptions.HTTPError: If the request fails, likely due to lack of admin permissions
        """
        url = f"{self.base_url}/ocs/v1.php/cloud/users"
        
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
        
    def search_user_details(self, search_term: str) -> dict:
        """
        Searches for user details based on a search term using the Nextcloud API.
        This is an administrative API call and requires admin privileges.
        
        Args:
            search_term: The search term to look for users
            
        Returns:
            A dictionary containing the user details data
            
        Raises:
            requests.exceptions.HTTPError: If the request fails, likely due to lack of admin permissions
        """
        url = f"{self.base_url}/ocs/v2.php/cloud/users/details"
        
        params = {
            "search": search_term
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
        
    def get_user_by_username(self, username: str) -> dict:
        """
        Fetches and returns information about a specific user by their username.
        This is an administrative API call and requires admin privileges.
        
        Args:
            username: The username of the user to fetch information for
            
        Returns:
            A dictionary containing the user data
            
        Raises:
            requests.exceptions.HTTPError: If the request fails, likely due to lack of admin permissions
        """
        url = f"{self.base_url}/ocs/v2.php/cloud/users/{username}"
        
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_file_metadata_by_id(self, file_id: str, version_timestamp: str = None) -> dict:
        """
        Retrieves comprehensive metadata for a file directly by its ID.
        This is more efficient than getting the path first and then fetching the metadata.
        
        Args:
            file_id: The file ID to get metadata for
            version_timestamp: Optional timestamp to retrieve a specific version of the file
            
        Returns:
            A dictionary containing the complete metadata for the specified file
            
        Raises:
            ValueError: If the file was not found
            requests.exceptions.HTTPError: If the request fails
        """
        # Set headers for WebDAV request
        webdav_headers = {
            'Content-Type': 'application/xml',
        }
        
        # Create PROPFIND XML request for all properties
        propfind_xml = """<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <d:prop>
    <d:displayname />
    <d:getlastmodified />
    <d:getetag />
    <d:resourcetype />
    <d:getcontenttype />
    <d:getcontentlength />
    <oc:permissions />
    <oc:id />
    <oc:fileid />
    <oc:size />
    <oc:favorite />
    <oc:share-types />
    <oc:owner-id />
    <oc:owner-display-name />
    <nc:creation_time />
    <nc:upload_time />
    <nc:has-preview />
  </d:prop>
</d:propfind>"""
        
        # If version_timestamp is provided, use the version-specific endpoint
        if version_timestamp:
            url = f"{self.base_url}/remote.php/dav/versions/{self.username}/versions/{file_id}/{version_timestamp}"
        else:
            # Get the file path from its ID
            file_info = self.get_path_by_file_id(file_id)
            file_path = file_info.get('path', '')
            
            # Check if the file was found in trashbin
            is_trashbin = file_path.startswith('/trash')
            
            # Format the URL based on whether the file is in trashbin or active files
            if is_trashbin:
                # Remove '/trash' prefix for trashbin path
                trashbin_path = file_path[6:] if file_path.startswith('/trash') else file_path
                url = f"{self.base_url}/remote.php/dav/trashbin/{self.username}/trash{trashbin_path}"
            else:
                # For active files, use the normal WebDAV endpoint
                url_path = f"remote.php/dav/files/{self.username}{file_path}"
                url = f"{self.base_url}/{url_path}"
        
        # Make request to get file metadata
        try:
            response = self.session.request('PROPFIND', url, headers=webdav_headers, data=propfind_xml, params={'depth': '0'})
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404 and version_timestamp:
                # Specific error message for version not found
                raise ValueError(f"Version with timestamp {version_timestamp} not found for file ID: {file_id}")
            raise
        
        # Parse XML response
        file_items = self._parse_files_response(response.content)
        
        # Return the first item (should be only one since depth=0)
        if file_items and len(file_items) > 0:
            metadata = file_items[0]
            
            # Add file_id to the metadata for convenience
            metadata['fileid'] = file_id
            
            # Add version information if this is a versioned file request
            if version_timestamp:
                metadata['version_timestamp'] = version_timestamp
                metadata['is_version'] = True
                metadata['source'] = 'version'
            else:
                # Add source information (active or trashbin)
                metadata['source'] = 'trashbin' if file_path.startswith('/trash') else 'active'
            
            return metadata
        else:
            if version_timestamp:
                raise ValueError(f"Version with timestamp {version_timestamp} not found for file ID: {file_id}")
            else:
                raise ValueError(f"Could not find metadata for file ID: {file_id}")
            
    def get_file_versions(self, file_id: str) -> list:
        """
        Fetches and returns all versions of a file from the Nextcloud server.
        
        Args:
            file_id: The file ID to query versions for
            
        Returns:
            A list of version items with their properties
            
        Raises:
            ValueError: If the file has no versions or versions could not be retrieved
            requests.exceptions.HTTPError: If the request fails
        """
        # Set headers for WebDAV request
        webdav_headers = {
            'Content-Type': 'application/xml',
            'Depth': '1',  # We want all direct children (versions)
        }
        
        # Create PROPFIND XML request for version properties
        propfind_xml = """<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <d:prop>
    <d:displayname />
    <d:getlastmodified />
    <d:getetag />
    <d:getcontenttype />
    <d:getcontentlength />
    <oc:size />
  </d:prop>
</d:propfind>"""
        
        # Format URL for versions endpoint
        url = f"{self.base_url}/remote.php/dav/versions/{self.username}/versions/{file_id}"
        
        try:
            # Make request to versions endpoint
            response = self.session.request('PROPFIND', url, headers=webdav_headers, data=propfind_xml)
            response.raise_for_status()
            print(response.content)
            
            # Parse XML response
            root = ET.fromstring(response.content)
            
            # Extract version information
            versions = []
            
            # Start from index 1 to skip the parent directory entry
            for response_tag in root.findall('.//{DAV:}response')[1:]:
                version = {}
                
                # Get the href (path)
                href = response_tag.find('.//{DAV:}href')
                if href is not None:
                    version['href'] = href.text
                    
                    # Extract version timestamp from the path
                    # The path format is typically /remote.php/dav/versions/username/versions/fileid/timestamp
                    path_parts = href.text.split('/')
                    if len(path_parts) > 0:
                        version['timestamp'] = path_parts[-1]  # Last part should be the timestamp
                
                # Get all properties with 200 OK status
                propstat = response_tag.find('.//{DAV:}propstat[{DAV:}status="HTTP/1.1 200 OK"]')
                if propstat is not None:
                    prop = propstat.find('.//{DAV:}prop')
                    
                    # Extract basic properties
                    displayname = prop.find('.//{DAV:}displayname')
                    if displayname is not None and displayname.text:
                        version['displayname'] = displayname.text
                    
                    lastmodified = prop.find('.//{DAV:}getlastmodified')
                    if lastmodified is not None and lastmodified.text:
                        version['lastmodified'] = lastmodified.text
                    
                    etag = prop.find('.//{DAV:}getetag')
                    if etag is not None and etag.text:
                        version['etag'] = etag.text.strip('"')
                    
                    contenttype = prop.find('.//{DAV:}getcontenttype')
                    if contenttype is not None and contenttype.text:
                        version['contenttype'] = contenttype.text
                    
                    contentlength = prop.find('.//{DAV:}getcontentlength')
                    if contentlength is not None and contentlength.text:
                        version['contentlength'] = int(contentlength.text)
                    
                    # Extract Nextcloud specific properties
                    size = prop.find('.//{http://owncloud.org/ns}size')
                    if size is not None and size.text:
                        version['size'] = int(size.text)
                
                versions.append(version)
            
            # Sort versions by timestamp in descending order (newest first)
            versions.sort(key=lambda x: x.get('timestamp', '0'), reverse=True)
            
            if not versions:
                return []  # Return empty list if no versions found
            
            return versions
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # File has no versions or doesn't exist
                return []
            raise

    def get_file_content(self, file_id: str, version_timestamp: str = None) -> bytes:
        """
        Retrieves the content of a file by its file ID.
        
        Args:
            file_id: The file ID to retrieve content for
            version_timestamp: Optional timestamp to retrieve a specific version of the file
            
        Returns:
            The raw content of the file as bytes
            
        Raises:
            ValueError: If the file was not found or if the specified version timestamp doesn't exist
            requests.exceptions.HTTPError: If the request fails
        """
        # If version_timestamp is provided, use the version-specific endpoint
        if version_timestamp:
            # Construct the versioned file URL
            url = f"{self.base_url}/remote.php/dav/versions/{self.username}/versions/{file_id}/{version_timestamp}"
            
            # First check if this version exists
            try:
                # Get metadata to validate the version exists
                self.get_file_metadata_by_id(file_id, version_timestamp)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    raise ValueError(f"Version with timestamp {version_timestamp} not found for file ID: {file_id}")
                raise
            except ValueError:
                raise ValueError(f"Version with timestamp {version_timestamp} not found for file ID: {file_id}")
        else:
            # Get the file path and href from our helper method
            file_info = self.get_path_by_file_id(file_id)
            
            # Use the complete href for the download URL
            url = f"{self.base_url}{file_info['href']}"
        
        # Get the file content with a single GET request
        response = self.session.get(url)
        response.raise_for_status()
        
        # Return the raw content
        return response.content

class NextCloudWebClient:
    """
    Client for interacting with Nextcloud via the web interface by mimicking browser behavior.
    This allows operations that are not available through the standard API.
    """
    
    def __init__(self, base_url: str, username: str, user_password: str, session_file=None, proxy: str = None, verify_ssl: bool = True, log_file: str = None):
        """
        Initializes the NextCloudWebClient with base URL, username, and user password.
        Attempts to load a saved session or performs a fresh login if required.
        
        Args:
            base_url: The base URL of the Nextcloud instance
            username: The username to authenticate with
            user_password: The user password (not app password) for web authentication
            session_file: Optional path to a saved session file to load instead of logging in
            proxy: Optional proxy server in the format "http://ip:port" or "https://ip:port"
            verify_ssl: Whether to verify SSL certificates (default: True)
            log_file: Optional path to log all API requests and responses to a file
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = user_password
        self.session = requests.Session()
        
        # Initialize the logger
        self.logger = NextcloudLogger.get_instance(log_file)
        self.logger.info(f"Initializing NextCloudWebClient for {username}@{base_url}")
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy,
            }
        
        # Set SSL verification
        self.session.verify = verify_ssl
        if not verify_ssl:
            self.logger.warning("SSL certificate verification is disabled - this is insecure and should only be used for testing")
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Monkey patch the session to log all requests
        original_request = self.session.request
        
        def logging_request(method, url, **kwargs):
            self.logger.log_request(method, url, **kwargs)
            response = original_request(method, url, **kwargs)
            self.logger.log_response(response)
            return response
            
        self.session.request = logging_request
        
        # Try to load session from file if specified
        if session_file and self._load_session(session_file):
            print(f"Successfully loaded session from {session_file}")
        else:
            # Otherwise, perform a fresh login
            self._login()
    
    def _login(self):
        """
        Performs a web login to Nextcloud by:
        1. Getting the login page to extract request token
        2. Submitting login credentials with the request token
        3. Saving the session cookies and token for future use
        
        Raises:
            requests.exceptions.RequestException: If any request fails
            ValueError: If login fails or required tokens cannot be extracted
        """
        print(f"Logging in to {self.base_url} as {self.username}...")
        
        # Step 1: Get login page and extract request token
        login_page_url = f"{self.base_url}/login"
        response = self.session.get(login_page_url)
        response.raise_for_status()
        
        # Extract request token from HTML head
        request_token_match = re.search(r'data-requesttoken="([^"]+)"', response.text)
        if not request_token_match:
            raise ValueError("Could not extract request token from login page")
        
        request_token = request_token_match.group(1)
        
        # Step 2: Submit login form with extracted token
        login_url = f"{self.base_url}/login"
        
        # Use Europe/Berlin timezone instead of UTC based on working login request
        login_data = {
            'user': self.username,
            'password': self.password,
            'timezone': 'Europe/Berlin',
            'timezone_offset': '2',
            'requesttoken': request_token
        }
        
        # Set additional headers required for successful login
        login_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f"{self.base_url}/login",
            'Origin': self.base_url,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1'
        }
        
        login_response = self.session.post(login_url, data=login_data, headers=login_headers, allow_redirects=False)
        
        # Check if login was successful (should redirect with 303 status)
        if login_response.status_code != 303:
            # Print more detailed error information for troubleshooting
            print(f"Login failed with status code: {login_response.status_code}")
            print(f"Response headers: {login_response.headers}")
            print(f"Response content: {login_response.text[:500]}...")  # Print first 500 chars of response
            raise ValueError(f"Login failed with status code: {login_response.status_code}")
                
        # Follow the redirect to complete login process
        redirect_url = login_response.headers.get('Location', '')
        if redirect_url:
            # If it's a relative URL, prepend the base URL
            if not redirect_url.startswith('http'):
                redirect_url = f"{self.base_url}{redirect_url}"
                
            # Follow the redirect with the proper headers
            follow_headers = {
                'Referer': login_url,
                'Upgrade-Insecure-Requests': '1'
            }
            self.session.get(redirect_url, headers=follow_headers)
        
        # Save session data for future use
        self._save_session()
        
        print(f"Successfully logged in as {self.username}")
    
    def _save_session(self, file_path=None):
        """
        Saves the current session (cookies and tokens) to a JSON file.
        
        Args:
            file_path: Optional custom file path, otherwise uses "nextcloud_session_{username}.json"
        """
        if file_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = f"nextcloud_session_{self.username}_{timestamp}.json"
        
        # Extract cookies from session
        cookies_dict = {cookie.name: cookie.value for cookie in self.session.cookies}
        
        # Extract request token from existing headers if available
        request_token = None
        for cookie in self.session.cookies:
            if "nc_token" in cookie.name:
                request_token = cookie.value
                break
        
        # Save to JSON file
        session_data = {
            'username': self.username,
            'base_url': self.base_url,
            'cookies': cookies_dict,
            'request_token': request_token,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(file_path, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        print(f"Session data saved to {file_path}")
        
        return file_path
    
    def _load_session(self, file_path):
        """
        Loads a previously saved session from a JSON file.
        
        Args:
            file_path: Path to the JSON session file
            
        Returns:
            bool: True if session was successfully loaded, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                print(f"Session file not found: {file_path}")
                return False
                
            with open(file_path, 'r') as f:
                session_data = json.load(f)
            
            # Check if session data matches current user
            if session_data.get('username') != self.username or session_data.get('base_url') != self.base_url:
                print(f"Warning: Session file was created for different user or server.")
                return False
            
            # Load cookies into session
            if 'cookies' in session_data:
                for name, value in session_data['cookies'].items():
                    self.session.cookies.set(name, value)
            
            # Test if session is still valid
            try:
                test_url = f"{self.base_url}/index.php/apps/dashboard/"
                response = self.session.get(test_url)
                if response.status_code != 200 or "log in" in response.text.lower():
                    print("Session expired. Performing new login...")
                    return False
            except requests.exceptions.RequestException:
                print("Failed to validate session. Performing new login...")
                return False
                
            return True
                
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error loading session data: {str(e)}")
            return False

    def check_authentication(self):
        """
        Verifies if the current session is authenticated.
        
        Returns:
            bool: True if authenticated, False otherwise
        """
        try:
            # Try to access a page that requires authentication
            test_url = f"{self.base_url}/index.php/apps/files/"
            response = self.session.get(test_url)
            
            # If we get redirected to login or get a 401, we're not authenticated
            if response.status_code != 200 or "log in" in response.text.lower():
                return False
                
            return True
        except requests.exceptions.RequestException:
            return False
            
    def list_devices(self):
        """
        Retrieves a list of devices from the Nextcloud security page.
        This method extracts and parses the base64-encoded JSON data from the initial state
        hidden input field on the security page.
        
        Returns:
            dict: A dictionary containing parsed device information including name, type,
                  last activity time, and device ID, as well as the raw data.
                  
        Raises:
            requests.exceptions.RequestException: If the request fails
            ValueError: If the security page cannot be accessed or parsed
            ImportError: If BeautifulSoup is not installed
        """
        try:
            # Import BeautifulSoup for HTML parsing
            try:
                from bs4 import BeautifulSoup
                from datetime import datetime
                import base64
                import json
            except ImportError:
                raise ImportError("BeautifulSoup is required. Install it with 'pip install beautifulsoup4'")
            
            # Check if we're authenticated first
            if not self.check_authentication():
                raise ValueError("Not authenticated. Please log in first.")
                
            # Access the security page
            security_url = f"{self.base_url}/settings/user/security"
            response = self.session.get(security_url)
            response.raise_for_status()
            
            # Store the security page response for later operations
            self._security_page_response = response
            
            # Parse the HTML with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract request token while we're at it (needed for revoke/update operations)
            self._security_page_token = None
            
            # First check for data-requesttoken on html tag (most reliable)
            html_tag = soup.find('html')
            if html_tag and html_tag.has_attr('data-requesttoken'):
                self._security_page_token = html_tag['data-requesttoken']
            else:
                # Look for token in any element with data-requesttoken
                token_element = soup.find(attrs={'data-requesttoken': True})
                if token_element and 'data-requesttoken' in token_element.attrs:
                    self._security_page_token = token_element['data-requesttoken']
                else:
                    # Try meta tag as last resort
                    meta_token = soup.find('meta', {'name': 'requesttoken'})
                    if meta_token and meta_token.get('content'):
                        self._security_page_token = meta_token.get('content')
            
            # Find the hidden input field with the initial state data
            initial_state = soup.find('input', {'id': 'initial-state-settings-app_tokens'})
            
            if not initial_state or not initial_state.get('value'):
                return {
                    'devices': [],
                    'count': 0,
                    'raw_html': response.text,
                    'url': security_url,
                    'timestamp': datetime.now().isoformat(),
                    'error': 'Could not find devices data in the page'
                }
                
            # Get the base64 encoded value
            base64_data = initial_state.get('value')
            
            # Decode the base64 data
            try:
                decoded_data = base64.b64decode(base64_data)
                devices_data = json.loads(decoded_data)
            except Exception as e:
                return {
                    'devices': [],
                    'count': 0,
                    'raw_html': response.text,
                    'url': security_url,
                    'timestamp': datetime.now().isoformat(),
                    'error': f'Failed to decode device data: {str(e)}'
                }
            
            # Process the devices data
            devices = []
            
            for item in devices_data:
                device = {
                    'id': str(item.get('id', '')),
                    'name': item.get('name', 'Unknown Device'),
                    'last_activity_timestamp': item.get('lastActivity', 0) * 1000,  # Convert to milliseconds for consistency
                    'can_delete': item.get('canDelete', False),
                    'can_rename': item.get('canRename', False),
                    'is_current_session': item.get('current', False),
                }
                
                # Add formatted last activity time
                timestamp_sec = item.get('lastActivity', 0)
                device['last_activity'] = datetime.fromtimestamp(timestamp_sec).strftime('%Y-%m-%d %H:%M:%S')
                
                # Determine device type
                device_type = item.get('type', -1)
                if device_type == 0:
                    device['type'] = 'browser'
                elif device_type == 1:
                    # Check name for specific device identifiers
                    name = device['name'].lower()
                    if 'desktop client' in name:
                        device['type'] = 'desktop'
                    elif 'android' in name or 'ios' in name or 'iphone' in name:
                        device['type'] = 'mobile'
                    else:
                        device['type'] = 'app'
                else:
                    device['type'] = 'unknown'
                
                # Extract OS information from the name
                name = device['name'].lower()
                if 'android' in name:
                    device['device_os'] = 'Android'
                elif 'ios' in name or 'iphone' in name:
                    device['device_os'] = 'iOS'
                elif 'windows' in name:
                    device['device_os'] = 'Windows'
                elif 'mac os x' in name or 'macos' in name:
                    device['device_os'] = 'macOS'
                elif 'linux' in name:
                    device['device_os'] = 'Linux'
                
                # Access scope
                scope = item.get('scope', {})
                device['has_filesystem_access'] = scope.get('filesystem', False)
                
                devices.append(device)
            
            # Sort devices by last activity timestamp (most recent first)
            devices.sort(key=lambda x: x.get('last_activity_timestamp', 0), reverse=True)
            
            # Return the parsed data and raw content
            return {
                'devices': devices,
                'count': len(devices),
                'raw_data': devices_data,
                'url': security_url,
                'timestamp': datetime.now().isoformat()
            }
            
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Error accessing devices page: {str(e)}")
            
    def update_device(self, device_id, json_data):
        """
        Updates a device/app token's properties by sending a PUT request with a JSON object.
        
        Args:
            device_id: The ID of the device to update
            json_data: A dictionary containing the updated device properties
            
        Returns:
            bool: True if the update was successful, False otherwise
            
        Raises:
            ValueError: If the device cannot be found or updated
            requests.exceptions.HTTPError: If the request fails
        """
        try:
            # Check if we're authenticated first
            if not self.check_authentication():
                raise ValueError("Not authenticated. Please log in first.")
            
            # To update a device, we must get the security page first to have the right context
            security_url = f"{self.base_url}/settings/user/security"
            
            # First, list the devices to get the security page loaded and token from the right context
            try:
                devices_data = self.list_devices()
                # Try to get token that we extracted during list_devices
                if hasattr(self, '_security_page_token') and self._security_page_token:
                    request_token = self._security_page_token
                else:
                    # Fall back to getting a new token from the security page
                    request_token = self._get_current_request_token(security_url)
            except Exception:
                # If list_devices fails, just get the token directly
                request_token = self._get_current_request_token(security_url)
                
            if not request_token:
                raise ValueError("Could not retrieve request token, which is required to update a device")
            
            # Prepare the request to update the token
            update_url = f"{self.base_url}/settings/personal/authtokens/{device_id}"
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/plain, */*',
                'X-Requested-With': 'XMLHttpRequest',
                'requesttoken': request_token,
                'Referer': f"{self.base_url}/settings/user/security",
                'Origin': self.base_url
            }
            
            # Make the request to update the token
            update_response = self.session.put(update_url, headers=headers, json=json_data)
            update_response.raise_for_status()
            
            # Check if the update was successful (should return HTTP 200)
            if update_response.status_code == 200:
                return True
            else:
                return False
                
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Error updating device: {str(e)}")
            
    def set_filesystem_access(self, device_id, allow_access=True):
        """
        Sets filesystem access permission for a specific device/app token.
        
        Args:
            device_id: The ID of the device to modify permissions for
            allow_access: Boolean indicating whether to allow (True) or deny (False) filesystem access
            
        Returns:
            bool: True if the permission update was successful, False otherwise
            
        Raises:
            ValueError: If the device cannot be found or permissions cannot be updated
        """
        try:
            # Prepare the update data with the filesystem scope
            update_data = {
                'scope': {
                    'filesystem': allow_access
                }
            }
            
            # Call the update_device method with the prepared data
            return self.update_device(device_id, update_data)
                
        except Exception as e:
            raise ValueError(f"Error setting filesystem access: {str(e)}")
    
    def _get_current_request_token(self, page_url=None):
        """
        Get the current request token from a Nextcloud page.
        This is required for CSRF-protected actions like revoking devices.
        
        Args:
            page_url: Optional URL to get the token from. If not provided, uses dashboard.
                      For device operations, the security page should be used.
        
        Returns:
            str: The current request token, or None if not found
            
        Raises:
            requests.exceptions.RequestException: If the request fails
        """
        try:
            # For device operations, use the security page to get the correct token context
            if not page_url:
                page_url = f"{self.base_url}/settings/user/security"
                
            # Get the specified page to extract the token
            response = self.session.get(page_url)
            response.raise_for_status()
            
            # Store this response for later use with device operations
            if 'security' in page_url:
                self._security_page_response = response
            
            # First try to extract token from cookies - but cookies might not have the correct context token
            for cookie in self.session.cookies:
                if "nc_token" in cookie.name:
                    cookie_token = cookie.value
                    # Only return cookie token if we're not on the security page
                    if 'security' not in page_url:
                        return cookie_token
            
            # Extract token from HTML (more reliable for device operations)
            try:
                from bs4 import BeautifulSoup
                
                # Parse the HTML with BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for requesttoken in data attributes (most reliable method)
                token_element = soup.find(attrs={'data-requesttoken': True})
                if token_element and 'data-requesttoken' in token_element.attrs:
                    return token_element['data-requesttoken']
                
                # Check for requesttoken data on HTML tag
                html_tag = soup.find('html')
                if html_tag and html_tag.has_attr('data-requesttoken'):
                    return html_tag['data-requesttoken']
                
                # Check head elements for meta with requesttoken
                meta_token = soup.find('meta', {'name': 'requesttoken'})
                if meta_token and meta_token.get('content'):
                    return meta_token.get('content')
                    
            except ImportError:
                # Fall back to regex if BeautifulSoup is not available
                import re
                
                # Try HTML tag first
                html_match = re.search(r'<html[^>]*data-requesttoken="([^"]+)"', response.text)
                if html_match:
                    return html_match.group(1)
                    
                # Try other HTML elements with data-requesttoken attribute
                token_match = re.search(r'data-requesttoken="([^"]+)"', response.text)
                if token_match:
                    return token_match.group(1)
                    
                # Try meta tag pattern
                meta_match = re.search(r'<meta.*?name="requesttoken".*?content="([^"]+)"', response.text)
                if meta_match:
                    return meta_match.group(1)
                
            # If still not found, return None
            return None
                
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Error getting request token: {str(e)}")
            
    def revoke_device(self, device_id):
        """
        Revokes (deletes) a device/app token using its ID.
        
        Args:
            device_id: The ID of the device to revoke
            
        Returns:
            bool: True if revocation was successful, False otherwise
            
        Raises:
            ValueError: If the device cannot be found or revoked
        """
        try:
            # Check if we're authenticated first
            if not self.check_authentication():
                raise ValueError("Not authenticated. Please log in first.")
            
            # To revoke a device, we must get the security page first to have the right context
            security_url = f"{self.base_url}/settings/user/security"
            
            # First, list the devices to get the security page loaded and token from the right context
            try:
                devices_data = self.list_devices()
                # Try to get token that we extracted during list_devices
                if hasattr(self, '_security_page_token') and self._security_page_token:
                    request_token = self._security_page_token
                else:
                    # Fall back to getting a new token from the security page
                    request_token = self._get_current_request_token(security_url)
            except Exception:
                # If list_devices fails, just get the token directly
                request_token = self._get_current_request_token(security_url)
                
            if not request_token:
                raise ValueError("Could not retrieve request token, which is required to revoke a device")
            
            # Prepare the request to delete the token
            revoke_url = f"{self.base_url}/settings/personal/authtokens/{device_id}"
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'X-Requested-With': 'XMLHttpRequest',
                'requesttoken': request_token,
                'Referer': f"{self.base_url}/settings/user/security",
                'Origin': self.base_url
            }
            
            # Make the request to revoke the token
            revoke_response = self.session.delete(revoke_url, headers=headers)
            revoke_response.raise_for_status()
            
            # Check if the revocation was successful (should return HTTP 200)
            if revoke_response.status_code == 200:
                return True
            else:
                return False
                
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Error revoking device: {str(e)}")

