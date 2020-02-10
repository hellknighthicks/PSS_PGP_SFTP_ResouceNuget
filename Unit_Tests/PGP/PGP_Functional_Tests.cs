using System.IO;
using NUnit.Framework;
using PSS_PGP;
using Unit_Tests.PGP.Resource;

namespace Unit_Tests.PGP
{
    [TestFixture]
    [Category("PGP-Functional Tests")]
    public class PGP_Functional_Tests
    {

        [Test]
        public void PGPEncryptDecryptFile_Works_Full_Pass()
        {

            var testFileName = "testFile.txt";
            var testEncryptedFileName = "testFileEncrypted.txt";
            var testDecryptedFileName = "testFileDecrypted.txt";
            var testPrivateKeyFileName = "testPrivateKeyFile";
            var testText = "This Message is to be Encrypted and then Decrypted. :)";

            #region Cleanup from last run and setup for new
            if (File.Exists(testFileName))
            {
                File.Delete(testFileName);
            }

            if (File.Exists(testEncryptedFileName))
            {
                File.Delete(testEncryptedFileName);
            }

            if (File.Exists(testDecryptedFileName))
            {
                File.Delete(testDecryptedFileName);
            }

            if (File.Exists(testPrivateKeyFileName))
            {
                File.Delete(testPrivateKeyFileName);
            }

            File.Create(testFileName).Dispose();

            using (TextWriter tw = new StreamWriter(testFileName))
            {
                tw.WriteLine(testText);
            }

            File.Create(testPrivateKeyFileName).Dispose();

            using (TextWriter tw = new StreamWriter(testPrivateKeyFileName))
            {
                tw.WriteLine(PGP_Test_Variables.PrivateKey);
            }
#endregion

            var success = PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.PublicKey);

            Assert.IsTrue(success, "Failed to populate Public Key from String!!!!");

            var fileInfo = new FileInfo(testFileName);

            PSS_PGPEncrypt.EncryptFile(fileInfo, testEncryptedFileName,false,false);

            Assert.IsTrue(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be TRUE and isn't!!!");
            Assert.IsTrue(File.Exists(testEncryptedFileName),"No Encrypted File was found.  Encryption has failed.");

            var testFileText = File.ReadAllText(testFileName);
            var testEncryptedFileText = File.ReadAllText(testEncryptedFileName);
            
            Assert.IsFalse(testFileText.Equals(testEncryptedFileText),"Encryption Failed the file contents are the same!!!");

            PSS_PGPDecrypt.DecryptFileAndOutputToFile(testEncryptedFileName,testPrivateKeyFileName, PGP_Test_Variables.Passcode,testDecryptedFileName);

            var testFileDecrypted = File.ReadAllText(testDecryptedFileName);

            Assert.IsTrue(testFileDecrypted.Equals(testFileText),"Text from before encryption and after encryption should be the same. They were Not!!");

        }

        [Test]
        public void PGPEncryptDecryptFileStream_Works_Full_Pass()
        {

            var testFileName = "testFile.txt";
            var testEncryptedFileName = "testFileEncrypted.txt";
            var testText = "This Message is to be Encrypted and then Decrypted. :)";

            if (File.Exists(testFileName))
            {
                File.Delete(testFileName);
            }

            if (File.Exists(testEncryptedFileName))
            {
                File.Delete(testEncryptedFileName);
            }

            File.Create(testFileName).Dispose();

            using (TextWriter tw = new StreamWriter(testFileName))
            {
                tw.WriteLine(testText);
            }

            var success = PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.PublicKey);

            Assert.IsTrue(success, "Failed to populate Public Key from String!!!!");

            var fileInfo = new FileInfo(testFileName);

            PSS_PGPEncrypt.EncryptFile(fileInfo, testEncryptedFileName, false, false);

            Assert.IsTrue(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be TRUE and isn't!!!");
            Assert.IsTrue(File.Exists(testEncryptedFileName), "No Encrypted File was found.  Encryption has failed.");

            var testFileText = File.ReadAllText(testFileName);
            var testEncryptedFileText = File.ReadAllText(testEncryptedFileName);

            Assert.IsFalse(testFileText.Equals(testEncryptedFileText), "Encryption Failed the file contents are the same!!!");

            PSS_PGPDecrypt.PopulatedPrivateKeyAndPassword(PGP_Test_Variables.PrivateKey, PGP_Test_Variables.Passcode);

            using (var fileStream = new FileStream(testEncryptedFileName, FileMode.Open))
            {

                var decryptedStream = PSS_PGPDecrypt.DecryptStream(fileStream);

                var reader = new StreamReader(decryptedStream);
                
                var testResult = reader.ReadToEnd().Trim();

                Assert.IsTrue(testText.Equals(testResult),"Original Text should be the same as the decrypted text and its not!!!");

            }
        }

        //[TestMethod]
        //public void PGPEncryptDecryptStrings_Works()
        //{
        //    var testString = @"ƅ̌苝娩峊ࠁ言㛬倯䰠ɋ鸳힪莭覥ꈷ跉醣¿ÿ拲ↈ줆兀ɗ얌핈⛾䊫窆鍟寛骇ᚩ�臒ﳺ䍽퇌囝则ม྆誵ㆣ洵簭濾섃틉鹸莐馯흷괬覀琺鎿䠝쯐宣↎饦岿䉈ჸ鴌䪏ө뀰㔒�ꌓ嫫㆐뾛㑺椆˟싱방鶎呐ᶣ΅뗏닍蟊�䀵糛痨牢幹늸鿷꺨깉樯몘ꖌਊꜢ䔂㘀籥揇䛴ὂ㯄勹ㅊ䜼運뉻湇쭖䤩ᕨ擴㸈爬꺙줝봉瓛♀�ᒨ쌭ṁ睎维楹ꊽ▊ﻥ⧈䈐䀭ᡔ㲦鋃䫊뫳㘹鿂ۑᩃ샀죽箘శ齉钉ᕋᐑ팻吅뤴䳈";

        //    //var testText = "This Message is to be Encrypted and then Decrypted. :)";

        //    //Assert.IsTrue(PSS_PGPEncrypt.PopulatePublicKey(PGP_Test_Variables.PublicKey), "Failed to populate Public Key from String!!!!");

        //    //Assert.IsTrue(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be TRUE and isn't!!!");

        //    //var encryptedString = PSS_PGPEncrypt.EncryptString(testText);

        //    //Assert.IsFalse(testText.Equals(encryptedString), "Encryption Failed the file contents are the same!!!");

        //    Assert.IsTrue(PSS_PGPDecrypt.PopulatedPrivateKeyAndPassword(PGP_Test_Variables.PrivateKey, PGP_Test_Variables.Passcode), 
        //        "PSS_PGPDecrypt.PopulatedPrivateKeyAndPassword should return true and didn't.");

        //    var testResult = PSS_PGPDecrypt.DecryptString(testString);

        //   // Assert.IsTrue(testText.Equals(testResult), "Original Text should be the same as the decrypted text and its not!!!");

        //}

    }
}
