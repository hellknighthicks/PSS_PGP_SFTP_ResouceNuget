using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSS_SFTP;

namespace Unit_Tests
{
    [TestClass]
    public class SFTP_ConnectionTests
    {
        [TestMethod]
        public void FtpConnector_ConnectionTestUnSuccessful_ReturnsFalse()
        {
            var ftpObject = new PSS_SFTPConnector("test",22,"TestUser","TestPassword");

            Assert.IsFalse(ftpObject.ConnectionTestResult,"Connection to Fake Server Returned TRUE!!!! And it shouldn't have");
        }
    }
}
