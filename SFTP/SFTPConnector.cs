using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PSS_SFTP
{
    public class PSS_SFTPConnector
    {

        private string
            _serverAddress,
            _userName,
            _password,
            _pathFromRoot;

        private int _serverPort;

        public bool ConnectionTestResult { get; set; }

        public List<Exception> ConnectionExceptions { get; private set; }

        private SftpClient _serverConnection;

        /// <summary>
        /// Sets up the connection objects.
        /// Tests the connection and will throw exception if connection issue occurs.
        /// </summary>
        /// <param name="server">Server Address</param>
        /// <param name="port">Port number to connect too</param>
        /// <param name="user">UserName</param>
        /// <param name="password">Password</param>
        /// <param name="path">path from home directory</param>
	    public PSS_SFTPConnector(string server, int port, string user, string password, string path = null)
        {
            LocalVarSetup();
            _serverAddress = server;
            _serverPort = port;
            _userName = user;
            _password = password;

            _pathFromRoot = string.IsNullOrWhiteSpace(path) ? string.Empty : path;

            _serverConnection = new SftpClient(_serverAddress, _serverPort, _userName, _password);

            TestConnection();

            CheckForDirectory(true);
        }

        /// <summary>
        /// Internal constructor for Local Variables that require setup.
        /// </summary>
        private void LocalVarSetup()
        {
            ConnectionExceptions = new List<Exception>();
        }

        /// <summary>
        /// Tests the FTP connection
        /// </summary>
        /// <returns>True if the connection works,  False if it does not.</returns>
        public bool TestConnection()
        {

            var returnVal = false;

            try
            {
                _serverConnection.Connect();
                returnVal = _serverConnection.IsConnected;
            }
            catch (Exception e)
            {
                ConnectionExceptions.Add(e);
            }
            finally
            {
                _serverConnection.Disconnect();
                ConnectionTestResult = false;
            }

            ConnectionTestResult = returnVal;

            return returnVal;
        }

        /// <summary>
        /// This Method will check for the directory you asked for.  If its not there and you tell it to it will attempt to create it.
        /// </summary>
        /// <param name="addTheDirectory">If the requested directory doesn't exits create it?  Recursive in nature.</param>
        /// <returns>True if it found it or created it.  False if it couldn't find it or create it.</returns>
        public bool CheckForDirectory(bool addTheDirectory = false)
        {

            Connect();

            if (!string.IsNullOrWhiteSpace(_pathFromRoot)&&_pathFromRoot.Contains('/'))
            {
                var pathToTest = _pathFromRoot.Trim('/').Split('/');

                var stepper = string.Empty;

                foreach (var dir in pathToTest)
                {
                    if (ListDirectoryContents(stepper).Contains(dir))
                    {
                        stepper += $"/{dir}";
                    }
                    else
                    {
                        if (addTheDirectory)
                        {
                            stepper += $"/{dir}";

                            try
                            {
                                _serverConnection.CreateDirectory(stepper);
                            }
                            catch (Exception e)
                            {
                                ConnectionExceptions.Add(new Exception($"The Desired Path didn't exist and I was unable to create it {stepper}",e));
                                return false;
                            }
                        }
                        else
                        {
                            return false;
                        }
                    }
                }

                return true;
            }

                //Tests the Root Directory to make sure that we can get a listing... Whether it contains anything or not we don't really care. 
            try
            {
                ListDirectoryContents(_pathFromRoot);
            }
            catch (Exception e)
            {
                ConnectionExceptions.Add(new Exception ("Directory list results failed for Root Path with no Sub Directory!!!",e));

                Disconnect();

                return false;
            }

            Disconnect();

            return true;
        }

        private bool Connect()
        {
            if (!_serverConnection.IsConnected)
            {
                _serverConnection.Connect();
            }

            return _serverConnection.IsConnected;
        }

        private void Disconnect()
        {
            _serverConnection.Disconnect();
        }

        /// <summary>
        /// Gets the directory list
        /// </summary>
        /// <returns>List with directories and file names.</returns>
        public List<string> ListDirectoryContents(string additionalPath)
        {
            var disconnect = false;

            if (_serverConnection.IsConnected)
            {
                Connect();
                disconnect = true;
            }


            var dirContents = _serverConnection.ListDirectory(additionalPath);

            var contentList = dirContents.Select(item => item.Name).ToList();

            if (disconnect)
            {
                Disconnect();
            }

            return contentList;
        }

        /// <summary>
        /// Uploads Specified file to SFTP server
        /// </summary>
        /// <param name="file">The actual file you want to upload.</param>
        /// <param name="fileInfo">Descriptor of file you want to upload.</param>
        /// <param name="verify">Method will ask for directory list and verify whether the file was uploaded or not.</param>
        /// <returns></returns>
        public string UploadFile(FileStream file, FileInfo fileInfo, bool verify = false)
        {

            if (file == null)
            {
                ConnectionExceptions.Add(new Exception("UploadFile: file Parameter cannot be null"));

                return "File Required";
            }
            if (!Connect())
            {
                return "Unable to Upload File The Connection Failed.";
            }
            try
            {
                _serverConnection.UploadFile(file, _pathFromRoot + fileInfo.Name);
            }
            catch (Exception e)
            {
                ConnectionExceptions.Add(e);
                return "Failed to Upload file.";
            }
            finally
            {
                Disconnect();
            }

            if (verify)
            {
                return FileOrDirectoryExists(fileInfo.Name) ? $"Successfully Uploaded and Verified {fileInfo.Name}" : "Uploaded Failed, File was not found after Upload.";
            }

            return $"Successfully Uploaded {fileInfo.Name}";
        }

        /// <summary>
        /// Uploads Specified Stream to SFTP server
        /// </summary>
        /// <param name="file">The actual file you want to upload.</param>
        /// <param name="fileInfo">Descriptor of file you want to upload.</param>
        /// <param name="verify">Method will ask for directory list and verify whether the file was uploaded or not.</param>
        /// <returns></returns>
        public string UploadFile(Stream file, FileInfo fileInfo, bool verify = false)
        {
            return UploadFile(file, fileInfo.Name, verify);
        }

        /// <summary>
        /// Uploads Specified Stream to SFTP server
        /// </summary>
        /// <param name="file">The actual file you want to upload.</param>
        /// <param name="fileName">Name of File to be written</param>
        /// <param name="verify">Method will ask for directory list and verify whether the file was uploaded or not.</param>
        /// <returns></returns>
        public string UploadFile(Stream file, string fileName, bool verify = false)
        {
            if (file == null)
            {
                ConnectionExceptions.Add(new Exception("UploadFile: file Parameter cannot be null"));

                return "File Required";
            }
            if (!Connect())
            {
                ConnectionExceptions.Add(new Exception("UploadFile: Connection to SFTP Server Failed."));
                return "Unable to Upload File The Connection Failed.";
            }
            try
            {
                _serverConnection.UploadFile(file, _pathFromRoot + fileName);
            }
            catch (Exception e)
            {
                ConnectionExceptions.Add(e);
                return "Failed to Upload file.";
            }
            finally
            {
                Disconnect();
            }

            if (verify)
            {
                return FileOrDirectoryExists(fileName) ?
                    $"{fileName} - Upload Complete and Verified " :
                    $"{fileName} - Uploaded Failed, File was not found after Upload.";
            }

            return $"{fileName} - Upload Complete";
        }

        /// <summary>
        /// Verifies that a file or directory with specified name exists in the current path
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public bool FileOrDirectoryExists(string name)
        {
            return ListDirectoryContents(_pathFromRoot).Contains(name);
        }

        /// <summary>
        /// Only call this when your done.  Cleans up SFTP objects.
        /// </summary>
        public void Dispose()
        {
            _serverConnection.Disconnect();
            _serverConnection.Dispose();
        }
    }
}
