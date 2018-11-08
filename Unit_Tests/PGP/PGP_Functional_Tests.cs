using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSS_PGP;

namespace Unit_Tests.PGP
{
    [TestClass]
    public class PGP_Functional_Tests
    {
        #region PGP Variables
        private string PGPPublicKey =
            @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG C# v1.6.1.0

mQENBFvctD8BCAC72g6eFT8W0GXnvePl4O1z9tJ/BORI8CbPq91yGxwz3rSBVp2q
lrnpEgJjo4/gGvtC6qGs3DdkpW4oOZ+zGXesxPqy1hwxlFVZZSSkKZIGVnXl8wHE
gaV/j7KMypl/wJDazG36MnEvSvHTJgjCrKNtaqdBt8kpDXj8XRas6iNaDIld2clT
Kch0Z6WGiog+HVzy7my5uFR9m4mYBS/1zasfe66pbmhz+7iblHf1FbmPOEFQX2rk
caoUwwLLglJR7oxa6JcQ3RzoxFoo3H5MR4Jr1xKVcFSL3+82ButaBsp1mAMuQy7h
v89AuSy9IxOxB/OxiBUQEt6yZc2a7tmGfWnDABEBAAG0GXByb3NpbHZlcnN5dGVt
c0BnbWFpbC5jb22JARwEEAECAAYFAlvctD8ACgkQ92FsJxfpytxMIQf/RRYpI3l0
ZeQhEtOKUIIGvIKccTUb7I7u0KQnm3i1H22/eqHACbXasbCcSeLC/ASJtYkH81IC
Jg2H0TFKFik9gVvfZtGf8TABoK21yHSg/jJou1xJI3EkBKmOC8XV9Nu5lPhGFFrW
Aobr09zJsMy4QhI83OOeuZ4beGgrY+vhFjHNLiZZvunW0xcHBtXIhsUeJd34AxsC
hJLBZo7JUfD8lqYBUncam4c8/HAnHW3ph4/oWFPZYwiDmE23bFElUczr0NOYAWkl
Z8oXVuw3Y92td9CWyKSCxLQKfL52m5GWal+ujOUTXUXEHf7/lIbgtA5l2XWdbIZV
7gYZyMyDlAog8Q==
=9+dK
-----END PGP PUBLIC KEY BLOCK-----";

#endregion

        [TestMethod, TestCategory("PGP-Functional Tests")]
        public void PGPEncrypt_PopulateKey_FromString_Works()
        {
            var success = PSS_PGPEncrypt.PopulatePublicKey(PGPPublicKey);

            Assert.IsTrue(success,"Failed to populate Public Key from String!!!!");
            Assert.IsTrue(PSS_PGPEncrypt.IsPublicKeyPopulated, "PSS_PGPEncrypt.IsPublicKeyPopulated Should be TRUE and isn't!!");
        }

    }
}
