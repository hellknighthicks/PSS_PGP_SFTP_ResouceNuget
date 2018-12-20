using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSS_SFTP;

namespace Unit_Tests.SFTP
{
    [TestClass]
    public class SFTP_Functional_ConnectionTests
    {
        [TestMethod, TestCategory("SFTP-Functional Connection Tests")]
        public void FtpConnector_ConnectionTestUnSuccessful_ReturnsFalse()
        {
            //Honestly not letting this get to the real network for this test would be ideal..  We need a Mock or Shim

            var ftpObject = new PSS_SFTPConnector("SomeRandomBunchaCRAP21323423", 22, "TestUser", "TestPassword");

            Assert.IsFalse(ftpObject.ConnectionTestResult, "Connection to Fake Server Returned TRUE!!!! And it shouldn't have.");
            Assert.AreEqual(ftpObject.ConnectionExceptions.Count,1,"Connection to Fake Server should only Produce 1 Exception.");
            Assert.AreEqual(ftpObject.ConnectionExceptions[0].Message, "No such host is known","Host Connection Exception string mismatch.");
        }

        [TestMethod, TestCategory("SFTP-Functional Connection Tests")]
        public void FtpConnector_ConnectionTestSuccessful_ReturnsTrue()
        {

            //ToDo: Fix this test
            //Honestly not letting this get to the real network for this test would be ideal..  We need a Mock or Shim

            //var ftpObject = new PSS_SFTPConnector("demo.wftpserver.com", 2222, "demo-user", "demo-user");

            //Assert.IsTrue(ftpObject.ConnectionTestResult, "Connection to Real Server Returned False!!!! And it shouldn't have.");
            //Assert.AreEqual(ftpObject.ConnectionExceptions.Count, 0, "Connection to Real Server should Produce 0 Exception.");
            
        }
    }
}
