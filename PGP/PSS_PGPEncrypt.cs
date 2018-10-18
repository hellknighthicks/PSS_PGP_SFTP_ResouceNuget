using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Text;

namespace PSS_PGP
{
    /// <summary>
    /// Basic methods needed to preform PGP encryption using Bouncy Castle Nuget Package.
    /// </summary>
    public class PSS_PGPEncrypt
    {
        private static PgpPublicKey _populatedPublicKey;

        /// <summary>
        /// Takes a File and Encrypts it using the PGP Public Key. 
        /// Outputs a file to your Output file
        /// </summary>
        /// <param name="inputFile">File you wish to encrypt</param>
        /// <param name="outputFile">File name to output too</param>
        /// <param name="armor">Armor or Not to Armor the stream during encryption</param>
        /// <param name="integrityCheck"></param>
        public static void EncryptFile(FileInfo inputFile, string outputFile, bool armor = false, bool integrityCheck = true)
        {

            using (MemoryStream outputBytes = new MemoryStream())
            {
                PgpCompressedDataGenerator dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(dataCompressor.Open(outputBytes), PgpLiteralData.Binary,inputFile);

                dataCompressor.Close();
                PgpEncryptedDataGenerator dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, integrityCheck, new SecureRandom());

                dataGenerator.AddMethod(_populatedPublicKey);
                byte[] dataBytes = outputBytes.ToArray();

                using (Stream outputStream = File.Create(outputFile))
                {
                    try
                    {

                        if (armor)
                        {
                            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                            {
                                WriteStream(dataGenerator.Open(armoredStream, dataBytes.Length), ref dataBytes);
                            }
                        }
                        else
                        {
                            WriteStream(dataGenerator.Open(outputStream, dataBytes.Length), ref dataBytes);
                        }
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Unable to Encrypt File", e);
                    }
                }
            }
        }

        /// <summary>
        /// Populates the public key for methods to use without having to pass it every time. 
        /// Also prevents the need to include any Bouncy castle reference outside of here. 
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        public static bool PopulatePublicKey( Stream inputStream)
        {

            try
            {
                _populatedPublicKey = ReadPublicKey(inputStream);

                return _populatedPublicKey != null;
            }
            catch
            {
                return false;
            }

        }

        /// <summary>
        /// Opens Key Ring File and loads first available key
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            // iterate through the key rings.
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Search Keyring for the corresponding Key ID if Exists
        /// </summary>
        /// <param name="pgpSec">KeyRing Collection</param>
        /// <param name="keyId">keyId were looking for.</param>
        /// <param name="pass">Password to decrypt with.</param>
        /// <returns></returns>
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            var pgpSecKey = pgpSec.GetSecretKey(keyId);

            return pgpSecKey?.ExtractPrivateKey(pass);
        }

        /// <summary>
        /// Decrypts the byte array passed in and returns it as a byte array.
        /// </summary>
        /// <param name="inputData">Data to Encrypt</param>
        /// <param name="keyIn">Stream from your Key Ring File</param>
        /// <param name="passCode">Password for PGP encrypted bytes</param>
        /// <returns></returns>
        public static byte[] DecryptBytes(byte[] inputData, Stream keyIn, string passCode)
        {

            byte[] error = Encoding.ASCII.GetBytes("ERROR");

            using (Stream inputStream = new MemoryStream(inputData))
            {
                using (var decoderStream = PgpUtilities.GetDecoderStream(inputStream))
                {
                    using (MemoryStream decoded = new MemoryStream())
                    {

                        try
                        {
                            var pgpF = new PgpObjectFactory(decoderStream);
                            PgpEncryptedDataList enc;
                            var pGPObject = pgpF.NextPgpObject();

                            // First piece of object might be a PGP marker packet.
                            if (pGPObject is PgpEncryptedDataList list)
                                enc = list;
                            else
                                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                            // find secret key
                            PgpPrivateKey sKey = null;
                            PgpPublicKeyEncryptedData pbEncrypted = null;
                            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                            PgpUtilities.GetDecoderStream(keyIn));
                            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                            {
                                sKey = FindSecretKey(pgpSec, pked.KeyId, passCode.ToCharArray());
                                if (sKey != null)
                                {
                                    pbEncrypted = pked;
                                    break;
                                }
                            }
                            if (sKey == null)
                                throw new ArgumentException("ERROR - Secret key for message not found.");

                            using (var clear = pbEncrypted.GetDataStream(sKey))
                            {
                                var plainFact = new PgpObjectFactory(clear);
                                var message = plainFact.NextPgpObject();

                                if (message is PgpCompressedData cData)
                                {
                                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());
                                    message = pgpFact.NextPgpObject();
                                }
                                if (message is PgpLiteralData ld)
                                {
                                    var unc = ld.GetInputStream();
                                    Streams.PipeAll(unc, decoded);
                                }
                                else if (message is PgpOnePassSignatureList)
                                    throw new PgpException("encrypted message contains a signed message - not literal data.");
                                else
                                    throw new PgpException("message is not a simple encrypted file - type unknown.");
                            }
                            if (pbEncrypted.IsIntegrityProtected())
                            {
                                Console.WriteLine(!pbEncrypted.Verify()
                                    ? "PGP Error - Message failed integrity check."
                                    : "PGP - Message integrity check passed.");
                            }
                            else
                            {
                                Console.WriteLine("PGP - No message integrity check.");
                            }

                            return decoded.ToArray();
                        }
                        catch (Exception e)
                        {
                            if (e.Message.StartsWith("Checksum mismatch"))
                                Console.WriteLine("PGP Invalid Passcode - Likely invalid passcode. Possible data corruption.");
                            else if (e.Message.StartsWith("Object reference not"))
                                Console.WriteLine("PGP Error - data does not exist.");
                            else if (e.Message.StartsWith("Premature end of stream"))
                                Console.WriteLine("PGP Error - Partial PGP data found.");
                            else
                                Console.WriteLine($"PGP Error - {e.Message}");

                            Exception underlyingException = e.InnerException;

                            if (underlyingException != null)
                                Console.WriteLine($"PGP Error - {underlyingException.Message}");

                            return error;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// This method allows for reuse without passing the key every time.  
        /// However it will throw an error if the PopulatedPublicKey is not set before calling.
        /// </summary>
        /// <param name="inputData">byte array to encrypt</param>
        /// <param name="withIntegrityCheck">check the data for errors</param>
        /// <param name="armor">protect the data streams</param>
        /// <returns></returns>
        public static byte[] EncryptBytes(byte[] inputData, bool withIntegrityCheck, bool armor = false)
        {
            if(_populatedPublicKey ==null)
            { throw new ArgumentNullException("Public Key Must Be Populated before Encrypting!!!!!"); }

            byte[] processedData = CompressBytes(inputData, PgpLiteralData.Console, CompressionAlgorithmTag.Uncompressed);

            using (MemoryStream bOut = new MemoryStream())
            {
                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                encGen.AddMethod(_populatedPublicKey);

                using (Stream output = bOut)
                {
                    try
                    {
                        if (!armor)
                        { return EncryptNonArmored(processedData, bOut, output, encGen); }
                        else
                        { return EncryptArmored(processedData, bOut, output, encGen); }
                    }
                    catch (Exception e)
                    {
                        throw new Exception(" Unable to Encrypt", e);
                    }
                }
            }
        }

        private static byte[] EncryptNonArmored(byte[] processedData, MemoryStream bOut, Stream output, PgpEncryptedDataGenerator encGen)
        {
            using (var encOut = encGen.Open(output, processedData.Length))
            {
                encOut.Write(processedData, 0, processedData.Length);
                return bOut.ToArray();
            }
        }

        private static byte[] EncryptArmored(byte[] processedData, MemoryStream bOut, Stream output, PgpEncryptedDataGenerator encGen)
        {
            using (var armored = new ArmoredOutputStream(output))
            {
                using (var encOut = encGen.Open(armored, processedData.Length))
                {
                    encOut.Write(processedData, 0, processedData.Length);
                    return bOut.ToArray();
                }
            }
        }

        /// <summary>
        /// Compresses the Byte Array removing un-needed data based on the CompressionAlgorithmTag
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="fileName"></param>
        /// <param name="algorithm"></param>
        /// <returns>Compressed Bytes</returns>
        private static byte[] CompressBytes(byte[] clearData, string fileName, CompressionAlgorithmTag algorithm)
        {
            using (var bytesOut = new MemoryStream())
            {

                var compressedData = new PgpCompressedDataGenerator(algorithm);

                using (Stream compressedOutput = compressedData.Open(bytesOut))
                {
                    PgpLiteralDataGenerator literalData = new PgpLiteralDataGenerator();

                    // Im not sure if we want to use these features.  But compression might be useful.  It removes un-needed data.
                    try
                    {
                        using (var pOut = literalData.Open(compressedOutput, PgpLiteralData.Binary, fileName, clearData.Length, DateTime.UtcNow))
                        {

                            pOut.Write(clearData, 0, clearData.Length);
                            return bytesOut.ToArray();
                        }
                    }
                    catch(Exception e)
                    {
                        throw new Exception("Unable to Compress", e);
                    }
                }

            }
        }

        private static void WriteStream(Stream inputStream, ref byte[] dataBytes)
        {
            using (var outputStream = inputStream)
            {
                outputStream.Write(dataBytes, 0, dataBytes.Length);
            }
        }

    }
}
