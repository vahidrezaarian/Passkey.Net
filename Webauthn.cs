// WebauthnSharp
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of CtapSharp and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using CtapSharp;
using CtapSharp.Transports;
using Newtonsoft.Json.Linq;
using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace WebauthnLib
{
    public enum UserPresence
    {   
        Discouraged,
        Preferred,
        Required
    }

    public enum UserVerification
    {   
        Discouraged,
        Preferred,
        Required
    }

    public enum UserVerificationType
    {
        BuiltIn,
        ClientPin,
        None
    }

    public class UserVerificationMethod
    {
        public UserVerificationType Type;
        public byte[] PinToken;
        public int PinProtocol;

        public UserVerificationMethod(UserVerificationType type, byte[] pinToken = null, int pinProtocol = 1)
        {
            Type = type;
            PinToken = pinToken;
            PinProtocol = pinProtocol;
        }
    }

    public class Webauthn: IDisposable
    {
        private readonly Ctap _ctap;
        private class KeyAgreement
        {
            public readonly byte[] Secret;
            public readonly CBORObject PlatfromKeyAgreement;

            public KeyAgreement(byte[] secret, CBORObject platformPublicKey)
            {
                Secret = secret;
                PlatfromKeyAgreement = platformPublicKey;
            }
        }
        private KeyAgreement _keyAgreement;

        public Webauthn(FidoSecurityKeyDevice device) 
        {
            _ctap = new Ctap(device);
        }

        public void Dispose()
        {
            _ctap.Dispose();
        }

        public JObject Authenticate(string request, bool uv, bool up = true, string pin = null)
        {
            return Authenticate(JObject.Parse(request), uv, up, pin);
        }

        public JObject Authenticate(JObject request, bool uv, bool up = true, string pin = null)
        {
            JArray allowList = null;
            if (request.ContainsKey("allowCredentials"))
            {
                allowList = request["allowCredentials"] as JArray;
            }

            var userVerificationMethod = new UserVerificationMethod(UserVerificationType.None);
            if (pin != null)
            {
                var pinToken = GetPinToken(pin);
                userVerificationMethod = new UserVerificationMethod(UserVerificationType.ClientPin, pinToken);
            }
            else if (uv)
            {
                userVerificationMethod = new UserVerificationMethod(UserVerificationType.BuiltIn);
            }

            JObject extensions = null;
            if (request.ContainsKey("extensions"))
            {
                extensions = request["extensions"] as JObject;
            }

            return Authenticate(request["challenge"].ToString(), request["rpId"].ToString(), allowList, userVerificationMethod, up, extensions);
        }

        public JObject Authenticate(string challenge, string rpid, JArray allowedCredentials = null, UserVerificationMethod userVeritifcationMethod = null, bool userPresence = true, JObject extensions = null, int timeout = 60000)
        {
            var clientDataJson = CreateClientDataJson(challenge, rpid);
            var clientDataHash = Utilities.ComputeSha256(Encoding.UTF8.GetBytes(clientDataJson.ToString(Newtonsoft.Json.Formatting.None)));
            CBORObject allowList = null;
            CBORObject extensionsCbor = null;
            byte[] pinAuth = null;
            int pinProtocol = 1;

            if (allowedCredentials != null)
            {
                allowList = CreateCborCredentialsListFromJson(allowedCredentials);
            }

            if (extensions != null)
            {
                extensionsCbor = CreateAuthenticationExtensionCbor(extensions);
            }

            var options = CreateAuthenticationOptionsCbor(userVeritifcationMethod != null && userVeritifcationMethod.Type == UserVerificationType.BuiltIn, userPresence);

            if (userVeritifcationMethod != null && userVeritifcationMethod.Type == UserVerificationType.ClientPin)
            {
                var hmac = new HMACSHA256(userVeritifcationMethod.PinToken);
                pinAuth = hmac.ComputeHash(clientDataHash).Take(16).ToArray();
                pinProtocol = userVeritifcationMethod.PinProtocol;
            }

            var response = _ctap.GetAssertion(rpid, clientDataHash, allowList?.EncodeToBytes(), extensionsCbor?.EncodeToBytes(), options?.EncodeToBytes(), pinAuth, pinProtocol);
            return CreateAuthenticationResultJson(response.ToCborObject(), clientDataJson);
        }

        public JObject Register(string request, bool uv, bool rk = true, string pin = null)
        {
            return Register(JObject.Parse(request), uv, rk, pin);
        }

        public JObject Register(JObject request, bool uv, bool rk = true, string pin = null)
        {
            JArray excludeCredentials = null;
            if (request.ContainsKey("excludeCredentials"))
            {
                excludeCredentials = request["excludeCredentials"] as JArray;
            }

            JObject extensions = null;
            if (request.ContainsKey("extensions"))
            {
                extensions = request["extensions"] as JObject;
            }

            var userVerificationMethod = new UserVerificationMethod(UserVerificationType.None);
            if (pin != null)
            {
                var pinToken = GetPinToken(pin);
                userVerificationMethod = new UserVerificationMethod(UserVerificationType.ClientPin, pinToken);
            }
            else if (uv)
            {
                userVerificationMethod = new UserVerificationMethod(UserVerificationType.BuiltIn);
            }

            return Register(request["challenge"].ToString(), request["rp"] as JObject, request["user"] as JObject,
                request["pubKeyCredParams"] as JArray, excludeCredentials, extensions, userVerificationMethod, rk);
        }

        public JObject Register(string challenge, JObject rp, JObject user, JArray publickCredParams, JArray excludedCredentials = null, JObject extensions = null, UserVerificationMethod userVeritifcationMethod = null, bool residentKey = false, int timeout = 60000)
        {
            var clientDataJson = CreateClientDataJson(challenge, rp["id"].ToString());
            var clientDataHash = Utilities.ComputeSha256(Encoding.UTF8.GetBytes(clientDataJson.ToString(Newtonsoft.Json.Formatting.None)));
            CBORObject excludeList = null;
            CBORObject extensionsCbor = null;
            byte[] pinAuth = null;
            int pinProtocol = 1;

            if (excludedCredentials != null)
            {
                excludeList = CreateCborCredentialsListFromJson(excludedCredentials);
            }

            if (extensions != null)
            {
                extensionsCbor = CreateRegistrationExtensionsCborObject(extensions);
            }

            var options = CreateRegistrationOptionsCbor(userVeritifcationMethod != null && userVeritifcationMethod.Type == UserVerificationType.BuiltIn, residentKey);

            if (userVeritifcationMethod != null && userVeritifcationMethod.Type == UserVerificationType.ClientPin)
            {
                var hmac = new HMACSHA256(userVeritifcationMethod.PinToken);
                pinAuth = hmac.ComputeHash(clientDataHash).Take(16).ToArray();
                pinProtocol = userVeritifcationMethod.PinProtocol;
            }

            var response = _ctap.MakeCredential(clientDataHash, CBORObject.FromJSONString(rp.ToString(Newtonsoft.Json.Formatting.None))?.EncodeToBytes(), CreateUserCborObjectFromJson(user)?.EncodeToBytes(),
                CBORObject.FromJSONString(publickCredParams.ToString(Newtonsoft.Json.Formatting.None))?.EncodeToBytes(), excludeList?.EncodeToBytes(), extensionsCbor?.EncodeToBytes(), options?.EncodeToBytes(), pinAuth, pinProtocol);
            return CreateRegistrationResultJson(response.ToCborObject(), clientDataJson);
        }

        public JObject GetSecurityKeyInfo()
        {
            return JObject.Parse(_ctap.GetInfo().ToCborObject().ToJSONString());
        }

        public int GetPinRetries()
        {
            var ctapResponse = _ctap.GetPinRetries().ToCborObject();
            if (!ctapResponse.ContainsKey(3))
            {
                throw new Exception("Invalid response from Authenticator");
            }
            return ctapResponse[3].AsInt32();
        }

        public byte[] GetPinToken(string pin, int pinProtocol = 1)
        {
            if (_keyAgreement == null)
            {
                _keyAgreement = GetKeyAgreement();
            }

            byte[] pinHash = Utilities.ComputeSha256(Encoding.UTF8.GetBytes(pin));
            byte[] pinHashHalf = new byte[16];
            Array.Copy(pinHash, pinHashHalf, 16);
            var pinHashEnc = Utilities.Encrypt(pinHashHalf, _keyAgreement.Secret, new byte[16]);
            var pinTokenEnc = _ctap.GetPinToken(pinHashEnc, _keyAgreement.PlatfromKeyAgreement, pinProtocol).ToCborObject()[2].GetByteString();
            return Utilities.Decrypt(pinTokenEnc, _keyAgreement.Secret, new byte[16]);
        }

        private KeyAgreement GetKeyAgreement()
        {
            var authenticatorPublicKey = _ctap.GetKeyAgreement().ToCborObject()[1];

            using (ECDiffieHellmanCng platform = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256))
            {
                platform.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                platform.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] secret;

                using (ECDiffieHellman authenticator = ECDiffieHellman.Create(authenticatorPublicKey.ToElipticCurveParameters()))
                {
                    secret = platform.DeriveKeyFromHash(authenticator.PublicKey, HashAlgorithmName.SHA256);
                }

                ECParameters parameters = platform.ExportParameters(false);

                byte[] x = parameters.Q.X;
                byte[] y = parameters.Q.Y;

                Dictionary<int, object> platformPublickKeyCose = new Dictionary<int, object>
                    {
                        { 1, 2 },
                        { -1, 1 },
                        { 3, -25 },
                        { -2, x },
                        { -3, y }
                    };

                var platformPublicKey = CBORObject.FromObject(platformPublickKeyCose);

                return new KeyAgreement(secret, platformPublicKey);
            }
        }

        private static JObject CreateClientDataJson(string challenge, string rpid, string type = "webauthn.get")
        {
            return new JObject()
            {
                ["type"] = type,
                ["challenge"] = challenge,
                ["origin"] = $"https://{rpid}"
            };
        }

        private static CBORObject CreateCborCredentialsListFromJson(JArray credentialsListJson)
        {
            var cborCredentialsList = CBORObject.NewArray();
            foreach (var cred in credentialsListJson.Cast<JObject>())
            {
                var credentialCbor = CBORObject.NewMap();
                credentialCbor.Add("id", cred["id"].ToString().ToByteArrayFromBase64UrlString());
                credentialCbor.Add("type", cred["type"].ToString());
                var transportsCbor = CBORObject.NewArray();
                if (cred.ContainsKey("transports") && (cred["transports"] as JArray).HasValues)
                {
                    var transportsJson = cred["transports"] as JArray;
                    foreach (var transport in transportsJson)
                    {
                        transportsCbor.Add(transport);
                    }
                }
                else
                {
                    transportsCbor.Add("usb");
                }
                credentialCbor.Add("transports", transportsCbor);
                cborCredentialsList.Add(credentialCbor);
            }
            return cborCredentialsList;
        }

        private static CBORObject CreateUserCborObjectFromJson(JObject user)
        {
            var userCbor = CBORObject.NewMap();
            userCbor.Add("id", user["id"].ToString().ToByteArrayFromBase64UrlString());
            userCbor.Add("name", user["name"].ToString());
            userCbor.Add("displayName", user["displayName"].ToString());
            return userCbor;
        }

        #region AuthenticationCeremonyHelpers
        private static CBORObject CreateAuthenticationOptionsCbor(bool userVerification, bool userPresence)
        {
            var options = CBORObject.NewMap();
            options.Add("up", userPresence);
            options.Add("uv", userVerification);
            return options;
        }

        private static ulong ExtractSignCountFromAuthData(byte[] authData)
        {
            var signCountBytes = new byte[4];
            Array.Copy(authData, 33, signCountBytes, 0, 4);
            if (BitConverter.IsLittleEndian)
            {
                signCountBytes.Reverse();
            }
            return BitConverter.ToUInt64(signCountBytes, 0);
        }

        private JObject ExtractAuthenticationExtensionResultsFromAuthData(byte[] authData)
        {
            using (var ms = new MemoryStream(authData))
            {
                ms.Seek(32, SeekOrigin.Begin);

                byte flags = (byte)ms.ReadByte();
                bool hasAttestedCredData = (flags & 0x40) != 0;
                bool hasExtensions = (flags & 0x80) != 0;

                ms.Seek(4, SeekOrigin.Current);

                if (hasAttestedCredData) // Skipping the attested data to get to the extensions
                {
                    var aaguid = new byte[16];
                    ms.Read(aaguid, 0, 16);

                    byte[] lenBuf = new byte[2];
                    ms.Read(lenBuf, 0, 2);
                    ushort credIdLen = (ushort)((lenBuf[0] << 8) | lenBuf[1]);

                    byte[] credentialId = new byte[credIdLen];
                    ms.Read(credentialId, 0, credIdLen);

                    CBORObject.Read(ms);
                }

                if (hasExtensions)
                {
                    var clientExtensionResults = new JObject();
                    var cborExtensions = CBORObject.Read(ms);
                    if (cborExtensions.ContainsKey("hmac-secret"))
                    {
                        var hmacSecret = cborExtensions["hmac-secret"].GetByteString();
                        var first = new byte[32];
                        Array.Copy(hmacSecret, first, 32);
                        var saltResult1 = Utilities.Decrypt(first, _keyAgreement.Secret, new byte[16]).ToBase64UrlString();
                        string saltResult2 = null;
                        clientExtensionResults["hmacGetSecret"] = new JObject()
                        {
                            ["output1"] = saltResult1
                        };
                        if (hmacSecret.Length > 32)
                        {
                            var second = new byte[32];
                            Array.Copy(hmacSecret, 32, second, 0, 32);
                            saltResult2 = Utilities.Decrypt(second, _keyAgreement.Secret, new byte[16]).ToBase64UrlString(); ;
                            clientExtensionResults["hmacGetSecret"]["output2"] = saltResult2;
                        }

                        var results = new JObject()
                        {
                            ["first"] =saltResult1
                        };
                        if (saltResult2 != null)
                        {
                            results["second"] = saltResult2;
                        }
                        clientExtensionResults["prf"] = new JObject()
                        {
                            ["results"] = results
                        };
                    }
                    return clientExtensionResults;
                }
                else return null;
            }
        }

        private CBORObject CreateAuthenticationHmacSecretExtension(byte[] salt1, byte[] salt2)
        {
            if (_keyAgreement == null)
            {
                _keyAgreement = GetKeyAgreement();
            }

            byte[] saltEnc;
            byte[] saltAuth;
            var saltLength = salt2 == null ? 32 : 64;
            var salt = new byte[saltLength];
            Array.Copy(salt1, 0, salt, 0, 32);
            if (salt2 != null)
            {
                Array.Copy(salt2, 0, salt, 32, 32);
            }

            saltEnc = Utilities.Encrypt(salt, _keyAgreement.Secret, new byte[16], PaddingMode.None);
            var hmac = new HMACSHA256(_keyAgreement.Secret);
            saltAuth = hmac.ComputeHash(saltEnc).Take(16).ToArray();

            var hmacSecret = CBORObject.NewMap();
            hmacSecret.Add(1, _keyAgreement.PlatfromKeyAgreement);
            hmacSecret.Add(2, saltEnc);
            hmacSecret.Add(3, saltAuth);
            return hmacSecret;
        }

        private CBORObject CreateAuthenticationExtensionCbor(JObject extensionsJson)
        {
            var extensionsCbor = CBORObject.NewMap();

            if (extensionsJson.ContainsKey("hmacGetSecret"))
            {
                var hmacGetSecret = extensionsJson["hmacGetSecret"] as JObject;
                var salt1 = hmacGetSecret["salt1"].ToString().ToByteArrayFromBase64UrlString();
                byte[] salt2 = null;
                if (hmacGetSecret.ContainsKey("salt2"))
                {
                    salt2 = hmacGetSecret["salt2"].ToString().ToByteArrayFromBase64UrlString();
                }
                extensionsCbor.Add("hmac-secret", CreateAuthenticationHmacSecretExtension(salt1, salt2));
            }
            else if (extensionsJson.ContainsKey("prf"))
            {
                var prf = extensionsJson["prf"] as JObject;
                if (prf.ContainsKey("eval"))
                {
                    var eval = prf["eval"] as JObject;
                    var salt1 = eval["first"].ToString().ToByteArrayFromBase64UrlString();
                    byte[] salt2 = null;
                    if (eval.ContainsKey("second"))
                    {
                        salt2 = eval["second"].ToString().ToByteArrayFromBase64UrlString();
                    }
                    extensionsCbor.Add("hmac-secret", CreateAuthenticationHmacSecretExtension(salt1, salt2));
                }
            }

            if (extensionsCbor.Count > 0)
            {
                return extensionsCbor;
            }
            return null;
        }

        private JObject CreateAuthenticationResultJson(CBORObject authenticationResultCbor, JObject clientDataJson)
        {
            var credentialIdBytes = authenticationResultCbor[1]["id"].GetByteString();
            var credentialType = authenticationResultCbor[1]["type"].AsString();
            var authenticatorData = authenticationResultCbor[2].GetByteString();
            var signature = authenticationResultCbor[3].GetByteString();
            byte[] userHandle = null;

            if (authenticationResultCbor.ContainsKey(4))
            {
                var user = authenticationResultCbor[4];
                if (user.ContainsKey("id"))
                {
                    userHandle = user["id"].GetByteString();
                }
            }

            var clientExtensionResults = ExtractAuthenticationExtensionResultsFromAuthData(authenticatorData);

            var response = new JObject()
            {
                ["clientDataJSON"] = Encoding.UTF8.GetBytes(clientDataJson.ToString(Newtonsoft.Json.Formatting.None)).ToBase64UrlString(),
                ["authenticatorData"] = authenticatorData.ToBase64UrlString(),
                ["signature"] = signature.ToBase64UrlString()
            };
            if (userHandle != null)
            {
                response["userHandle"] = userHandle.ToBase64UrlString();
            }

            var result = new JObject()
            {
                ["id"] = credentialIdBytes.ToBase64UrlString(),
                ["rawId"] = credentialIdBytes.ToBase64UrlString(),
                ["type"] = credentialType,
                ["response"] = response
            };

            if (clientExtensionResults != null)
            {
                result["clientExtensionResults"] = clientExtensionResults;
            }
            return result;
        }
        #endregion

        #region RegistrationCeremonyHelpers
        private CBORObject CreateRegistrationOptionsCbor(bool userVerification, bool residentKey)
        {
            var options = CBORObject.NewMap();
            options.Add("rk", residentKey);
            options.Add("uv", userVerification);
            return options;
        }

        private JObject CreateRegistrationResultJson(CBORObject registrationResultCbor, JObject clientDataJson)
        {
            if (registrationResultCbor[1].AsString() != "packed")
            {
                throw new Exception("The attestation statement format is not supported!");
            }

            var authenticatorData = registrationResultCbor[2].GetByteString();

            var attestationObjectCbor = CBORObject.NewMap();
            attestationObjectCbor.Add("fmt", registrationResultCbor[1].AsString());
            attestationObjectCbor.Add("authData", authenticatorData);
            attestationObjectCbor.Add("attStmt", registrationResultCbor[3]);

            byte[] credentialId = null;
            JObject clientExtensionResult = null;

            using (var ms = new MemoryStream(authenticatorData))
            {
                ms.Seek(32, SeekOrigin.Begin);

                byte flags = (byte)ms.ReadByte();
                bool hasAttestedCredData = (flags & 0x40) != 0;
                bool hasExtensions = (flags & 0x80) != 0;

                ms.Seek(4, SeekOrigin.Current);

                if (hasAttestedCredData)
                {
                    var aaguid = new byte[16];
                    ms.Read(aaguid, 0, 16);

                    byte[] lenBuf = new byte[2];
                    ms.Read(lenBuf, 0, 2);
                    ushort credIdLen = (ushort)((lenBuf[0] << 8) | lenBuf[1]);

                    credentialId = new byte[credIdLen];
                    ms.Read(credentialId, 0, credIdLen);

                    CBORObject.Read(ms);
                }
                else
                {
                    throw new Exception("Invalid format!");
                }

                if (hasExtensions)
                {
                    var extensions = CBORObject.Read(ms);

                    clientExtensionResult = new JObject();

                    if (extensions.ContainsKey("hmac-secret"))
                    {
                        clientExtensionResult["hmacCreateSecret"] = extensions["hmac-secret"].AsBoolean();
                        if (extensions["hmac-secret"].AsBoolean())
                        {
                            clientExtensionResult["prf"] = new JObject()
                            {
                                ["enabled"] = true
                            };
                        }
                    }
                }
            }

            var response = new JObject()
            {
                ["clientDataJSON"] = Encoding.UTF8.GetBytes(clientDataJson.ToString(Newtonsoft.Json.Formatting.None)).ToBase64UrlString(),
                ["attestationObject"] = attestationObjectCbor.EncodeToBytes().ToBase64UrlString()
            };

            var result = new JObject()
            {
                ["id"] = credentialId.ToBase64UrlString(),
                ["rawId"] = credentialId.ToBase64UrlString(),
                ["type"] = "public-key",
                ["response"] = response
            };

            if (clientExtensionResult != null)
            {
                result["clientExtensionResult"] = clientExtensionResult;
            }
            return result;
        }

        private static CBORObject CreateRegistrationExtensionsCborObject(JObject extensionsJson)
        {
            var extensionsCbor = CBORObject.NewMap();
            if (extensionsJson.ContainsKey("hmacCreateSecret") && (bool)extensionsJson["hmacCreateSecret"])
            {
                extensionsCbor.Add("hmac-secret", true);
            }
            else if (extensionsJson.ContainsKey("prf"))
            {
                extensionsCbor.Add("hmac-secret", true);
            }

            if (extensionsJson.ContainsKey("enforceCredentialProtectionPolicy") && (bool)extensionsJson["enforceCredentialProtectionPolicy"])
            {
                extensionsCbor.Add("credProtect", 1);
            }

            if (extensionsCbor.Count > 0)
            {
                return extensionsCbor;
            }
            return null;
        }
        #endregion
    }
}
