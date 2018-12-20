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
        public static bool IsPublicKeyPopulated { get; private set; }

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

                IsPublicKeyPopulated = _populatedPublicKey != null;

                return IsPublicKeyPopulated;
            }
            catch
            {
                return false;
            }

        }

        /// <summary>
        /// Pass your public key in as a string.
        /// </summary>
        /// <param name="PublicKey">Assumes UTF8 Encoding</param>
        /// <returns></returns>
        public static bool PopulatePublicKey(string PublicKey)
        {
           return PopulatePublicKey(StringToStream(PublicKey));
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


        public static byte[] EncryptBytes(string inputstring, bool withIntegrityCheck, bool armor = false)
        {
            return EncryptBytes(Encoding.ASCII.GetBytes(inputstring), withIntegrityCheck, armor);
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
            if(!IsPublicKeyPopulated)
            { throw new ArgumentNullException("Public Key Must Be Populated before Encrypting!!!!!"); }

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
                        if (!armor)
                        { return EncryptNonArmored(processedData, bOut, output, encGen); }

                         return EncryptArmored(processedData, bOut, output, encGen); 
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
        /// <param name="integrityCheck"></param>
        public static void EncryptFile(FileInfo inputFile, string outputFile, bool armor = false, bool integrityCheck = true)
        {

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

        public static MemoryStream StringToStream(string toConvert)
        {
            // convert string to stream
            var byteArray = Encoding.Default.GetBytes(toConvert);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            var stream = new MemoryStream(byteArray);

            return stream;
        }

        public static string StreamToString(Stream stream)
        {
            stream.Position = 0;
            using (var reader = new StreamReader(stream, Encoding.Default))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
