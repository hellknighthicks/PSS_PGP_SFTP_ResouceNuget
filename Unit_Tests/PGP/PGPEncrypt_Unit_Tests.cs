using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSS_PGP;

namespace Unit_Tests.PGP
{
    [TestClass]
    [TestCategory("PGP-Encrypt - Unit Tests")]
    public class PGPEncrypt_Unit_Tests
    {

        [TestMethod]
        public void PGPDecrypt_DecryptFile_EmptyInputFileName_ThrowsException()
        {
       
            try
            {
                PSS_PGPDecrypt.DecryptFileAndOutputToFile("","",string.Empty);
            }
            catch (Exception e)
            {
                Assert.IsTrue(e is ArgumentNullException);
            }
        }

        [TestMethod]
        public void PGPDecrypt_DecryptFile_EmptyKeyFileName_ThrowsException()
        {

            try
            {
                PSS_PGPDecrypt.DecryptFileAndOutputToFile("fillerdata", "", string.Empty);
            }
            catch (Exception e)
            {
                Assert.IsTrue(e is ArgumentNullException);
            }
        }

        [TestMethod]
        public void PGPDecrypt_DecryptFile_EmptyInputStream_ThrowsException()
        {

            try
            {
                using (Stream input = null,keyIn = null)
                {
                    PSS_PGPDecrypt.DecryptFileAndOutputToFile(input, keyIn, string.Empty);
                }
            }
            catch (Exception e)
            {
                Assert.IsTrue(e is ArgumentNullException);
            }
        }

        [TestMethod]
        public void PGPDecrypt_DecryptFile_EmptyKeyInStream_ThrowsException()
        {

            try
            {
                using (Stream input = PSS_PGPEncrypt.StringToStream("TEST"), keyIn = null)
                {
                    PSS_PGPDecrypt.DecryptFileAndOutputToFile(input, keyIn, string.Empty);
                }
            }
            catch (Exception e)
            {
                Assert.IsTrue(e is ArgumentNullException);
            }
        }

    }
}
