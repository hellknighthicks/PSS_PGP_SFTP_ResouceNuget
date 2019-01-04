using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace PSS_PGP
{
    /// <summary>
    /// Basic methods needed to preform PGP encryption using Bouncy Castle Nuget Package.
    /// </summary>
    public class PSS_PGPEncrypt
    {
        private static PgpPublicKey _populatedPublicKey;
        private static string PublicKeyNotPopulatedText = "Public Key must be populated before calling this method.";

        public static bool IsPublicKeyPopulated { get; private set; }

        /// <summary>
        /// Populates the public key for methods to use without having to pass it every time. 
        /// Also prevents the need to include any Bouncy castle reference outside of here. 
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        public static bool PopulatePublicKey( Stream inputStream )
        {

            try
            {
                _populatedPublicKey = ReadPublicKey(inputStream);

                IsPublicKeyPopulated = _populatedPublicKey != null;

                return IsPublicKeyPopulated;
            }
            catch
            {
                IsPublicKeyPopulated = false;
                return false;
            }

        }

        /// <summary>
        /// Pass your public key in as a string.
        /// </summary>
        /// <param name="publicKey">Assumes UTF8 Encoding</param>
        /// <returns></returns>
        public static bool PopulatePublicKey(string publicKey)
        {
           return PopulatePublicKey(StringToStream(publicKey));
        }

        /// <summary>
        /// Opens Key Ring File and loads first available key
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            var pgpPub = new PgpPublicKeyRingBundle(inputStream);

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


        public static byte[] EncryptBytes(string inputString, bool withIntegrityCheck = true, bool armor = false)
        {
            if(string.IsNullOrWhiteSpace(inputString))
                throw new Exception("inputString must be populated.");

            if (!IsPublicKeyPopulated)
                throw new Exception(PublicKeyNotPopulatedText);

            return EncryptBytes(Encoding.ASCII.GetBytes(inputString), withIntegrityCheck, armor);
        }

        public static string EncryptString(string inputString, bool withIntegrityCheck = true, bool armor = false)
        {
            if (string.IsNullOrWhiteSpace(inputString))
                throw new ArgumentNullException(nameof(inputString));

            if (!IsPublicKeyPopulated)
                throw new Exception(PublicKeyNotPopulatedText);

            using (Stream stream =
                new MemoryStream(EncryptBytes(StringToStream(inputString).ToArray(), withIntegrityCheck, armor)))
            {
                return StreamToString(stream);
            }
        }

        /// <summary>
        /// This method allows for encryption without passing the private_key use.  
        /// However it will throw an error if the PopulatedPublicKey is not set before calling.
        /// </summary>
        /// <param name="inputData">byte array to encrypt</param>
        /// <param name="withIntegrityCheck">check the data for errors</param>
        /// <param name="armor">protect the data streams</param>
        /// <returns></returns>
        public static byte[] EncryptBytes(byte[] inputData, bool withIntegrityCheck = true, bool armor = false)
        {
            if(!(inputData.Length>0))
                throw new Exception("Must have more Bytes than that.");

            if (!IsPublicKeyPopulated)
                throw new Exception(PublicKeyNotPopulatedText);

            var processedData = CompressBytes(inputData, PgpLiteralData.Console, CompressionAlgorithmTag.Uncompressed);

            using (var bOut = new MemoryStream())
            {
                var encGen = new PgpEncryptedDataGenerator(
                    SymmetricKeyAlgorithmTag.Cast5, 
                    withIntegrityCheck, new SecureRandom());

                encGen.AddMethod(_populatedPublicKey);

                using (Stream output = bOut)
                {
                    try
                    {
                        return !armor ? 
                            EncryptNonArmored(processedData, bOut, output, encGen) : 
                            EncryptArmored(processedData, bOut, output, encGen);
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
        /// Takes a File and Encrypts it using the PGP Public Key. 
        /// Outputs a file to your Output file
        /// </summary>
        /// <param name="inputFile">File you wish to encrypt</param>
        /// <param name="outputFile">File name to output too</param>
        /// <param name="armor">Armor or Not to Armor the stream during encryption</param>
        /// <param name="integrityCheck">Adds a PGP check bit to insure the integrity of the data</param>
        public static void EncryptFile(FileInfo inputFile, string outputFile ="Encrypted.txt", bool armor = true, bool integrityCheck = true)
        {
            #region inputValidation
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));

            if (string.IsNullOrWhiteSpace(outputFile))
                throw new ArgumentNullException(nameof(outputFile));

            if (!IsPublicKeyPopulated)
                throw new Exception(PublicKeyNotPopulatedText);
            #endregion


            using (var outputBytes = new MemoryStream())
            {
                var dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(dataCompressor.Open(outputBytes), PgpLiteralData.Binary, inputFile);

                dataCompressor.Close();
                var dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, integrityCheck, new SecureRandom());

                dataGenerator.AddMethod(_populatedPublicKey);
                var dataBytes = outputBytes.ToArray();

                using (Stream outputStream = File.Create(outputFile))
                {
                    try
                    {

                        if (armor)
                        {
                            using (var armoredStream = new ArmoredOutputStream(outputStream))
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
        /// Converts a string to a steam
        /// </summary>
        /// <param name="toConvert"></param>
        /// <returns></returns>
        public static MemoryStream StringToStream(string toConvert)
        {
            // convert string to stream
            var byteArray = Encoding.Default.GetBytes(toConvert);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            var stream = new MemoryStream(byteArray);

            return stream;
        }

        /// <summary>
        /// Converts a stream to a regular old stream
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static string StreamToString(Stream stream)
        {
            var reader = new StreamReader(stream);

            return reader.ReadToEnd();
        }

        private static void WriteStream(Stream inputStream, ref byte[] dataBytes)
        {
            using (var outputStream = inputStream)
            {
                outputStream.Write(dataBytes, 0, dataBytes.Length);
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

                using (var compressedOutput = compressedData.Open(bytesOut))
                {
                    var literalData = new PgpLiteralDataGenerator();

                    try
                    {
                        using (var pOut = literalData.Open(compressedOutput, PgpLiteralData.Binary, fileName, clearData.Length, DateTime.UtcNow))
                        {

                            pOut.Write(clearData, 0, clearData.Length);
                            return bytesOut.ToArray();
                        }
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Unable to Compress", e);
                    }
                }

            }
        }

        //ToDo: Fix it or Kill it.
        //public static void CheckInputForNull<T>(T param)
        //{
        //    if (param ==null)
        //        throw new NullReferenceException(nameof(T));
        //    if (typeof(T) == string)


        //}
    }
}
