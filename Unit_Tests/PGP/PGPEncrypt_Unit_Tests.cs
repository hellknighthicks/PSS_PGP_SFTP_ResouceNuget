using System;
using System.IO;
using NUnit.Framework;
using PSS_PGP;

namespace Unit_Tests.PGP
{
    [TestFixture]
    [Category("PGP-Encrypt - Unit Tests")]
    public class PGPEncrypt_Unit_Tests
    {

        [Test]
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

        [Test]
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

        [Test]
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

        [Test]
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
