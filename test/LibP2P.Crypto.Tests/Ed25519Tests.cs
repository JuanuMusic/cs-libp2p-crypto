using System.Text;
using NUnit.Framework;

namespace LibP2P.Crypto.Tests
{
    public class Ed25519Tests
    {
        [Test]
        public void TestBasicSignAndVerify()
        {
            var pair = KeyPair.Generate(KeyType.Ed25519);
            var data = Encoding.UTF8.GetBytes("hello! and welcome to some awesome crypto primitives");

            var sig = pair.PrivateKey.Sign(data);
            var ok = pair.PublicKey.Verify(data, sig);
            Assert.True(ok);

            data[0] ^= data[0];
            ok = pair.PublicKey.Verify(data, sig);
            Assert.False(ok);
        }

        [Test]
        public void TestSignZero()
        {
            var pair = KeyPair.Generate(KeyType.Ed25519);
            var data = new byte[] {};

            var sig = pair.PrivateKey.Sign(data);
            var ok = pair.PublicKey.Verify(data, sig);

            Assert.True(ok);
        }

        [Test]
        public void TestMarshalLoop()
        {
            var pair = KeyPair.Generate(KeyType.Ed25519);

            var privB = pair.PrivateKey.Bytes;
            var privNew = PrivateKey.Unmarshal(privB);

            Assert.AreEqual(pair.PrivateKey, privNew);
            Assert.AreEqual(privNew, pair.PrivateKey);

            var pubB = pair.PublicKey.Bytes;
            var pubNew = PublicKey.Unmarshal(pubB);

            Assert.AreEqual(pair.PublicKey, pubNew);
            Assert.AreEqual(pubNew, pair.PublicKey);
        }

    }
}
