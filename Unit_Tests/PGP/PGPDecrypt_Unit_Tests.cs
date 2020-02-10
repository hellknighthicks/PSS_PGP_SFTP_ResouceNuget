using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using PSS_PGP;
using Unit_Tests.PGP.Resource;

namespace Unit_Tests.PGP
{
    [TestFixture]
    [Category("PGP-Decrypt - Unit Tests")]
    public class PGPDecrypt_Unit_Tests
    {

        [Test]
        public void PGPEncrypt_PopulateKey_FromString_Works()
        {
            var success = PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.PublicKey);

            Assert.IsTrue(success, "Failed to populate Public Key from String!!!!");
            Assert.IsTrue(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be TRUE and isn't!!");
        }
        [Test]
        public void PGPEncrypt_PopulateBadKey_FromString_Fails()
        {

            var success = PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.Bad_PublicKey);

            Assert.IsFalse(success, "Populated a Public Key from a bad String and shouldn't!!!!");
            Assert.IsFalse(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be FALSE and isn't!!");
        }

        [Test]
        public void PGPEncrypt_PopulateGoodKeyThenPopulateBadKey_FromString_Fails()
        {
            //Populate a good key
            PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.PublicKey);

            //Populate a bad key
            var success = PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.Bad_PublicKey);

            Assert.IsFalse(success, "Populated a Public Key from a bad String and shouldn't!!!!");
            Assert.IsFalse(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be FALSE and isn't!!");
        }

        [Test]
        public void PGPEncrypt_Encrypt_Encrypts()
        {
            var success = PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.PublicKey);

            var test_string = "Test this encryption!!!";

            var result = PSS_PGPEncrypt.EncryptBytes(Encoding.Default.GetBytes(test_string), true);

            var encryptedString = Encoding.ASCII.GetString(result);

            Assert.IsTrue(success, "Failed to populate Public Key from String!!!!");
            Assert.IsTrue(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be TRUE and isn't!!");
            Assert.IsFalse(encryptedString.Contains(test_string));
        }

        [Test]
        public void PGPEncrypt_StringToStream_StreamToStream_Works()
        {
            var testString = "Did I live?";
            const int numRuns = 30;

            var listOResults = new List<string>();

            for (var i = 0; i < numRuns; i++)
            {
                using (var streamTest = PSS_PGPEncrypt.StringToStream(i>0?listOResults[i-1]:testString))
                {
                    listOResults.Add(PSS_PGPEncrypt.StreamToString(streamTest));

                    Assert.IsTrue(testString.Equals(listOResults[i]),
                        "String to Stream Should have produced the same string as the starting one and did not!!!");
                }
            }

            Assert.AreEqual(numRuns,listOResults.Count,"The number of successful executions should match the number of runs and did not!!!");

        }

    }
}
