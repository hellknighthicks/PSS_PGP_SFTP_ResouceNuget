

namespace Unit_Tests.PGP.Resource
{
    class PGP_Test_Variables
    {


        public static string PublicKey =
            @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG C# v1.6.1.0

mQENBFvy+aMBCACi1I07nNanSIdmCBhv50sXDkKxMOqiYz524vr0zDJvWopkkal6
hI9QV6N6nsoHoU8aI1Iqwo1GSvvO5xMn0IjATOpxA8EpyAvdLDapCvZpU1FSdGru
IcEYexh+ntP4QqPukZVs25smeqD1ksX4TUAOZrM9X9Nq7I2hCTXLppstLxR5/0Bv
7gBWLEWEc/4TPrAkj6Cwd+D1kzYxRsYpXx2GLPU/CKQCo3JFI4qme1usMTwVHJE+
HD3ssqajXrC5/ou5KeOSwS7IenMjXylNhZGCq7cYkODk4e19FwdnHBp8dIZJA5VA
YWqs+SGUk9RvOdO9Bss2qx6KjHiewxylTQ1hABEBAAG0GnByb3NpbHZlcnN5c3Rl
bXNAZ21haWwuY29tiQEcBBABAgAGBQJb8vmjAAoJEL733YIpWspc3OMH/1fWXTm/
yitOYJXon+ShPvhCc5vW7DiO6Hcm1RQkSnZEtGcTruBoU3Jd3yGj6PtVV6LRdIVR
Yg6Cr5jm49XB+/yChIuaGFxwByLux1OcZyfJcId12fJAhZAJE8Wa9yZxxLttkjgk
iD4XOrBt7p/gqK2JpLgzJVe2dDu/Hj6UdaqUjDcXhnPFTDU49BGs8zSCAUrhoGMk
+fWsIBjsRwAlsVZhLsc7fwdWR0lKRJXSNkw0FcLIbuTXfR/kklC+bGEY8KSrpwrT
uHFQAoXo306QAoHO6szNPv7I5Ik9DMnJbE+ld8vWo2Hjx5L60A/rrwVadu5oRTcR
SEO3rJhjew9kjJU=
=LlBx
-----END PGP PUBLIC KEY BLOCK-----
";

        public static string PrivateKey =
            @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG C# v1.6.1.0

lQOsBFvy+aMBCACi1I07nNanSIdmCBhv50sXDkKxMOqiYz524vr0zDJvWopkkal6
hI9QV6N6nsoHoU8aI1Iqwo1GSvvO5xMn0IjATOpxA8EpyAvdLDapCvZpU1FSdGru
IcEYexh+ntP4QqPukZVs25smeqD1ksX4TUAOZrM9X9Nq7I2hCTXLppstLxR5/0Bv
7gBWLEWEc/4TPrAkj6Cwd+D1kzYxRsYpXx2GLPU/CKQCo3JFI4qme1usMTwVHJE+
HD3ssqajXrC5/ou5KeOSwS7IenMjXylNhZGCq7cYkODk4e19FwdnHBp8dIZJA5VA
YWqs+SGUk9RvOdO9Bss2qx6KjHiewxylTQ1hABEBAAH/AwMCDbyJFrba80RgUyzX
Xd/VClphvT7U7ScTa3kyps9BDzTXRlSl3Xny1cGQmInahyljbX4MZvNzN1980RdD
5k+MBWJ+wIql9fGy6CbC7BLkqcnMrZGCtJVqxrKuB0GSMOnzijRk7xlMmsfcABMd
WM5m4o2qwXYQbvEmKu7p42vca7rlQrXWt1MBRPlaoPe164C1QDVYXx5ngcg46Mg3
uOXvfalzjcjZp7ioZFHNTbMGURD+QuEfQ7bJsHJ4vVRP2arBMqOn9mqOniS+DeHz
txDtGLI6jzYz2ggQaVyfI+buzJaX5abNqKszXVN1yt0I8bSOW0qELvWjA6QCaQWm
3tauPlez0l4JTQ3lAczenM0Ggvmm27ZAYFmM/g6vPeWymLBhmSewd2/i5G8GzPUz
Os3n0wHO5vBbTKPvZMUIU9aI0LGxOFm3YjjZN4ynnqYWoL0weHtg1cbQ/5kdjMj0
lBJTxN0WwsTGDb1AOLpmV6cnMPdJcknQNc0hZ2GiPg0ti8cbqvAi0st0JxcgSCy0
6CpyjUD1E25mpcTPX8MjCHrxlXAXJ8GIIGLqGTM+y95iPLAa2VB0VS5JuYj4tP6v
USYUhC+afqiYGK28RWzDsbhAw15q1y+fioB4QE0ceWpmR8h9erolrTTefKQE266L
siCTYe6Z5fyPpnW+nXxH2yNDUZjPcjWxi1ZVe5RNlXfjKHliDJZqtl5VbmViJmO9
N/l8ozyV95/Ri4ga+imSh2MOG2CS3TgKOhq1jsw9UtCThbAtJ2cgZoC+/OUL/ORP
YBZhswaUqwk2eRt3Xm9kaljiUvtaBlt4LG5BYQg1oGlC0kkJcLqCo4I+4xa/Y70y
vK4RtznssguIr8s4ZbZzrvO5DbeZeY24tsPyNOiLk7QacHJvc2lsdmVyc3lzdGVt
c0BnbWFpbC5jb22JARwEEAECAAYFAlvy+aMACgkQvvfdgilaylzc4wf/V9ZdOb/K
K05gleif5KE++EJzm9bsOI7odybVFCRKdkS0ZxOu4GhTcl3fIaPo+1VXotF0hVFi
DoKvmObj1cH7/IKEi5oYXHAHIu7HU5xnJ8lwh3XZ8kCFkAkTxZr3JnHEu22SOCSI
Phc6sG3un+CorYmkuDMlV7Z0O78ePpR1qpSMNxeGc8VMNTj0EazzNIIBSuGgYyT5
9awgGOxHACWxVmEuxzt/B1ZHSUpEldI2TDQVwshu5Nd9H+SSUL5sYRjwpKunCtO4
cVAChejfTpACgc7qzM0+/sjkiT0MyclsT6V3y9ajYePHkvrQD+uvBVp27mhFNxFI
Q7esmGN7D2SMlQ==
=lqHt
-----END PGP PRIVATE KEY BLOCK-----";

        public static string Passcode = "Megazord55";

        public static string Bad_PublicKey = "Bad Key";

    }
}
