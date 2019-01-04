using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

namespace PSS_PGP
{
    public class PSS_PGPDecrypt
    {

        private static string _privateKey, _password;

        private const string
            DefaultFileName = "Decrypted.txt",
            PrivateKeyNotPopulatedText =
                "If your aren't passing a private key you must populate one prior to calling this method.";
        /// <summary>
        /// Used to allow the viewing and processing of log data of the package.
        /// </summary>
        public static List<string> EventLog = new List<string>();

        public static bool PrivateKeyPopulated => !string.IsNullOrWhiteSpace(_privateKey);

        public static bool PopulatedPrivateKeyAndPassword(string privateKey,string password = "")
        {
            if(string.IsNullOrWhiteSpace(privateKey))
            { throw new ArgumentException("You must defile a privateKey");}

            _privateKey = privateKey;
            _password = password;

            return PrivateKeyPopulated;
        }

        public static void DecryptFileAndOutputToFile(string inputFileName, string keyFileName, string password, string outputFileName = DefaultFileName)
        {
            if(string.IsNullOrWhiteSpace(inputFileName))
                throw new ArgumentNullException(nameof(inputFileName));
            if(string.IsNullOrWhiteSpace(keyFileName))
                throw new ArgumentNullException(nameof(keyFileName));

            using (Stream input = File.OpenRead(inputFileName),
                   keyIn = File.OpenRead(keyFileName))
            {
                DecryptFileAndOutputToFile(input, keyIn, password, outputFileName);
            }
        }

        public static void DecryptFileAndOutputToFile(Stream inputStream, Stream keyIn, string password, string outFileName = DefaultFileName)
        {
            if(inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if(keyIn == null)
                throw new ArgumentNullException(nameof(keyIn));

            if (string.IsNullOrWhiteSpace(outFileName))
            {
                throw new ArgumentNullException(nameof(outFileName));
            }

                Stream fOut = File.Create(outFileName);
                Streams.PipeAll(DecryptStream(inputStream, keyIn, password), fOut);
                fOut.Close();
        }

        public static void DecryptFileAndOutPutToFile(Stream inputStream, string outputFileName = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (!PrivateKeyPopulated)
                throw new Exception(PrivateKeyNotPopulatedText);

            Stream fOut = File.Create(outputFileName);
            Streams.PipeAll(DecryptStream(inputStream, PSS_PGPEncrypt.StringToStream(_privateKey), _password), fOut);
            fOut.Close();
        }

        /// <summary>
        /// The simplest and best way to Decrypt a stream
        /// Make sure you've populated PSSPGPDecrypt.PrivateKey(STRING) and Password(Optional)
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns>A Decrypted String</returns>
        public static Stream DecryptStream(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (!PrivateKeyPopulated)
                throw new Exception(PrivateKeyNotPopulatedText);

            using (var privateKeyStream = PSS_PGPEncrypt.StringToStream(_privateKey))
            {
                return DecryptStream(inputStream, privateKeyStream, _password);
            }
        }

        public static Stream DecryptStream(Stream inputStream, string keyFileName, string password)
        {
            if(inputStream==null)
                throw new ArgumentNullException(nameof(inputStream));
            if(string.IsNullOrWhiteSpace(keyFileName))
                throw new ArgumentNullException(nameof(keyFileName));

            using (Stream keyIn = File.OpenRead(keyFileName))
            {
                return DecryptStream(inputStream, keyIn, password);
            }
        }

        public static Stream DecryptStream(Stream inputStream, Stream keyIn, string password)
        {
            EventLog.Clear();

            if(inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if(keyIn==null)
                throw new ArgumentNullException(nameof(keyIn));

            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            Stream decryptedStream;
            try
            {

                var objectFactory = new PgpObjectFactory(inputStream);

                PgpEncryptedDataList encryptedDataList;

                var pgpObject = objectFactory.NextPgpObject();

                // First object may be a PGP marker packet.  If so skip it.

                if (pgpObject is PgpEncryptedDataList list)
                {
                    encryptedDataList = list;
                }
                else
                {
                    encryptedDataList = (PgpEncryptedDataList) objectFactory.NextPgpObject();
                }

                if (encryptedDataList == null)
                    throw new Exception("Cannot read encrypted data from input!!!  Unable to find PGP Data.  Are you sure this is encrypted?");


                // Find secret key

                PgpPrivateKey privateKey = null;

                PgpPublicKeyEncryptedData encryptedData = null;

                var pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpPublicKeyEncryptedData item in encryptedDataList.GetEncryptedDataObjects())
                {
                    privateKey = FindSecretKey(pgpSec, item.KeyId, password.ToCharArray());

                    if (privateKey == null) continue;

                    encryptedData = item;
                    break;
                }

                if (privateKey == null)
                {
                    throw new ArgumentException("Unable to Decrypt - A Secret key for the message was not found.");
                }

                var clear = encryptedData.GetDataStream(privateKey);

                var plainFact = new PgpObjectFactory(clear);

                var message = plainFact.NextPgpObject();

                if (message is PgpCompressedData cData)
                {
                    var pgpFact = new PgpObjectFactory(cData.GetDataStream());

                    message = pgpFact.NextPgpObject();
                }

                switch (message)
                {
                    case PgpLiteralData ld:
                        decryptedStream = ld.GetInputStream();
                        break;
                    case PgpOnePassSignatureList _:
                        throw new PgpException("The encrypted message contains a signed message - not literal data.");
                    default:
                        throw new PgpException("The message is not a simple encrypted file - type unknown.");
                }

                if (encryptedData.IsIntegrityProtected())
                {
                    EventLog.Add(!encryptedData.Verify()
                        ? "Message Failed integrity check!!!"
                        : "Message Passed the integrity check.");
                }
                else
                {
                    EventLog.Add("There was no integrity check");

                }
            }
            catch (PgpException e)
            {
                throw (Exception) e;
                //Console.Error.WriteLine(e);

                //if (e.InnerException != null)
                //{
                //    Console.Error.WriteLine(e.InnerException.Message);
                //    Console.Error.WriteLine(e.InnerException.StackTrace);
                //}
            }

            return decryptedStream;
        }

        /// <summary>
        /// It doesn't get any simpler than this.  Toss a PGP encrypted string in and get the unencrypted string out. 
        /// Make sure they PrivateKey and Password (If you have one) are populated
        /// </summary>
        /// <param name="encryptedString">Your PGP Encrypted String</param>
        /// <returns>Unencrypted String</returns>
        //public static string DecryptString(string encryptedString)
        //{
        //    if(string.IsNullOrWhiteSpace(encryptedString))
        //        throw new ArgumentNullException(nameof(encryptedString));

        //    using (var stream = PSS_PGPEncrypt.StringToStream(encryptedString))
        //    {
        //        return PSS_PGPEncrypt.StreamToString(DecryptStream(stream));
        //    }

        //}

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            var pgpSecKey = pgpSec.GetSecretKey(keyID);

            return pgpSecKey?.ExtractPrivateKey(pass);
        }
    }
}
