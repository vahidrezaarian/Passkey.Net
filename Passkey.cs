// Passkey.Net
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of Passkey.Net and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using CtapDotNet;
using CtapDotNet.Transports;
using Newtonsoft.Json.Linq;
using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasskeyDotNet
{
    /// <summary>
    /// Represents a passkey management system that facilitates the creation and authentication of passkeys using a FIDO
    /// security key device.
    /// </summary>
    /// <remarks>The Passkey class provides high-level methods for registering and authenticating passkeys in
    /// accordance with the FIDO2/WebAuthn standards. It manages user verification, PIN setup and changes, and handles
    /// user presence requirements. The class implements IDisposable to ensure proper cleanup of resources associated
    /// with the underlying CTAP instance. A user action callback can be supplied to prompt for user interactions, such
    /// as entering a PIN or touching the security key. Thread safety is not guaranteed; callers should ensure
    /// appropriate synchronization if accessing instances from multiple threads.</remarks>
    public class Passkey: IDisposable
    {
        private readonly Ctap _ctap;
        private readonly FidoSecurityKeyDevice _device;
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
        private Func<UserActionCallbackArgs, UserActionCallbackResult> _userActionCallback;

        /// <summary>
        /// Initializes a new instance of the Passkey class using the specified Fido security key device and an optional
        /// user action callback.
        /// </summary>
        /// <remarks>The user action callback is triggered when the device requires user presence or
        /// interaction. This allows custom handling of user prompts, such as displaying UI messages or logging events.
        /// If no callback is provided, user action events will not be handled explicitly.</remarks>
        /// <param name="device">The FidoSecurityKeyDevice that represents the security key to be used for authentication operations. Cannot
        /// be null.</param>
        /// <param name="userActionCallback">An optional callback that is invoked when user interaction is required, such as touching the security key.
        /// The callback receives a UserActionCallbackArgs instance and should return a UserActionCallbackResult
        /// indicating how to proceed.</param>
        public Passkey(FidoSecurityKeyDevice device, Func<UserActionCallbackArgs, UserActionCallbackResult> userActionCallback = null) 
        {
            _ctap = new Ctap(device);
            _device = device;
            _userActionCallback = userActionCallback;
            _device.UserActionRequiredEventHandler += (sender, args) =>
            {
                _userActionCallback?.Invoke(new UserActionCallbackArgs(UserActionCallbackActions.TouchSecurityKey));
            };
        }

        /// <summary>
        /// Releases all resources used by the current instance of the class.
        /// </summary>
        /// <remarks>Call this method when the object is no longer needed to free unmanaged resources and
        /// perform other cleanup operations. Failing to call this method may result in resource leaks.</remarks>
        public void Dispose()
        {
            _ctap.Dispose();
        }

        #region PasskeyCreationOverloads
        /// <summary>
        /// Creates a passkey using the specified request and user verification requirements.
        /// </summary>
        /// <remarks>The method parses the input request string into a JSON object before processing.
        /// Ensure that the request string is well-formed to avoid parsing errors.</remarks>
        /// <param name="request">A JSON-formatted string that defines the parameters for passkey creation. The string must be a valid JSON
        /// object.</param>
        /// <param name="userVerification">Specifies the level of user verification required during the passkey creation process.</param>
        /// <param name="userPresence">Indicates whether user presence is required as part of the passkey creation.</param>
        /// <returns>A JSON-formatted string representing the created passkey.</returns>
        public string Create(string request, UserVerification userVerification, UserPresence userPresence)
        {
            return Create(JObject.Parse(request), userVerification, userPresence).ToString(Newtonsoft.Json.Formatting.None);
        }

        /// <summary>
        /// Creates a new JSON object representing a credential creation request using the specified parameters and user
        /// verification requirements.
        /// </summary>
        /// <remarks>The method extracts relevant fields from the provided request object and applies the
        /// specified user verification and presence requirements. Optional excludeCredentials and extensions are
        /// included if present in the request.</remarks>
        /// <param name="request">A JSON object containing the credential creation request data, including fields such as challenge, relying
        /// party information, user information, public key credential parameters, and optional excludeCredentials and
        /// extensions.</param>
        /// <param name="userVerification">Specifies the user verification requirement to be enforced during the credential creation process.</param>
        /// <param name="userPresence">Indicates the user presence requirement that must be satisfied for the operation to proceed.</param>
        /// <returns>A JSON object containing the result of the credential creation process, including all necessary information
        /// for subsequent authentication steps.</returns>
        public JObject Create(JObject request, UserVerification userVerification, UserPresence userPresence)
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
            return Create(request["challenge"].ToString(), request["rp"] as JObject, request["user"] as JObject,
                request["pubKeyCredParams"] as JArray, userVerification, userPresence, excludeCredentials, extensions);
        }

        /// <summary>
        /// Creates a new JSON object representing a security credential creation request using the specified challenge,
        /// relying party, user information, supported credential parameters, user verification, user presence, and
        /// optional exclusions and extensions.
        /// </summary>
        /// <param name="challenge">The challenge string used to ensure the integrity and uniqueness of the credential creation request. Must
        /// not be null or empty.</param>
        /// <param name="rp">A JSON object containing information about the relying party, such as its name and identifier. Cannot be
        /// null.</param>
        /// <param name="user">A JSON object representing the user for whom the credential is being created, including user ID and display
        /// name. Cannot be null.</param>
        /// <param name="publickCredParams">An array of JSON objects specifying the public key credential parameters supported by the client. Cannot be
        /// null or empty.</param>
        /// <param name="userVerification">Specifies the user verification requirement for the credential creation process.</param>
        /// <param name="userPresence">Indicates the expected user presence requirement for the credential creation operation.</param>
        /// <param name="excludedCredentials">An optional array of JSON objects representing credentials that should be excluded from the creation
        /// process. May be null if no credentials are to be excluded.</param>
        /// <param name="extensions">An optional JSON object containing additional extension parameters for the credential creation request. May
        /// be null if no extensions are required.</param>
        /// <returns>A JSON object representing the assembled credential creation request, ready to be sent to the client for
        /// processing.</returns>
        public JObject Create(string challenge, JObject rp, JObject user, JArray publickCredParams, UserVerification userVerification, UserPresence userPresence, 
            JArray excludedCredentials = null, JObject extensions = null)
        {
            var securityKeyInfo = GetSecurityKeyInfo();
            CheckUserPresenceSatisfaction(securityKeyInfo, userPresence);
            CheckSupportedAlgorithms(securityKeyInfo, publickCredParams);
            var userVerificationMethod = GetUserVerificationMethod(securityKeyInfo, userVerification);
            return Create(challenge, rp, user, publickCredParams, excludedCredentials, extensions, userVerificationMethod, userPresence != UserPresence.Discouraged);
        }

        private JObject Create(string challenge, JObject rp, JObject user, JArray publickCredParams, JArray excludedCredentials = null, JObject extensions = null, UserVerificationMethod userVeritifcationMethod = null,
            bool residentKey = false)
        {
            var clientDataJson = CreateClientDataJson(challenge, rp["id"].ToString(), "webauthn.create");
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
        #endregion

        #region PasskeyAutheticationOverloads
        /// <summary>
        /// Authenticates a user based on the specified authentication request and verification requirements.
        /// </summary>
        /// <remarks>The method parses the input request string into a JSON object before performing
        /// authentication. Ensure that the request parameter is a valid JSON string to avoid parsing errors.</remarks>
        /// <param name="request">A JSON-formatted string that represents the authentication request. The string must be a valid JSON object.</param>
        /// <param name="userVerification">Specifies the level of user verification required for authentication. Possible values include None,
        /// Preferred, or Required.</param>
        /// <param name="userPresence">Indicates whether user presence is required during the authentication process. This parameter affects the
        /// security requirements for the operation.</param>
        /// <returns>A string containing the result of the authentication process, formatted as a JSON object. The result may
        /// include success or error information.</returns>
        public string Authenticate(string request, UserVerification userVerification, UserPresence userPresence)
        {
            return Authenticate(JObject.Parse(request), userVerification, userPresence).ToString(Newtonsoft.Json.Formatting.None);
        }

        /// <summary>
        /// Authenticates a user based on the provided authentication request and verification requirements.
        /// </summary>
        /// <remarks>The method extracts the challenge and rpId from the request and processes optional
        /// allowCredentials and extensions parameters if present. This overload simplifies authentication by accepting
        /// a single request object and verification options.</remarks>
        /// <param name="request">A JSON object containing the authentication request details, including the challenge, relying party
        /// identifier (rpId), and optional allowCredentials and extensions parameters.</param>
        /// <param name="userVerification">Specifies the user verification requirement for the authentication process. Determines whether user
        /// verification is required, preferred, or discouraged.</param>
        /// <param name="userPresence">Indicates whether user presence is required during authentication. Controls if the user must physically
        /// interact with the authenticator.</param>
        /// <returns>A JSON array containing the results of the authentication process, including any allowed credentials.</returns>
        public JArray Authenticate(JObject request, UserVerification userVerification, UserPresence userPresence)
        {
            JArray allowList = null;
            if (request.ContainsKey("allowCredentials"))
            {
                allowList = request["allowCredentials"] as JArray;
            }

            JObject extensions = null;
            if (request.ContainsKey("extensions"))
            {
                extensions = request["extensions"] as JObject;
            }

            return Authenticate(request["challenge"].ToString(), request["rpId"].ToString(), userVerification, userPresence, allowList, extensions);
        }

        /// <summary>
        /// Authenticates a user by verifying their response to a specified challenge using the provided relying party
        /// identifier, user verification, and user presence requirements.
        /// </summary>
        /// <param name="challenge">The challenge string that the user must respond to during the authentication process. This value is
        /// typically generated by the relying party to ensure the authenticity of the authentication attempt.</param>
        /// <param name="rpid">The identifier of the relying party requesting authentication. This value is used to scope the
        /// authentication to a specific service or application.</param>
        /// <param name="userVerification">Specifies the user verification requirement, such as biometric or PIN, that must be satisfied during
        /// authentication.</param>
        /// <param name="userPresence">Indicates the required level of user presence for the authentication process. Determines whether the user
        /// must be physically present or if presence is discouraged.</param>
        /// <param name="allowedCredentials">An optional array of credentials that are permitted for authentication. If null, all available credentials
        /// may be used.</param>
        /// <param name="extensions">An optional object containing additional parameters or extensions that may influence the authentication
        /// process.</param>
        /// <returns>A JArray containing the credentials that were successfully authenticated. The array is empty if no
        /// credentials are valid or authentication fails.</returns>
        public JArray Authenticate(string challenge, string rpid, UserVerification userVerification, UserPresence userPresence, JArray allowedCredentials = null, JObject extensions = null)
        {
            var securityKeyInfo = GetSecurityKeyInfo();
            CheckUserPresenceSatisfaction(securityKeyInfo, userPresence);
            var userVerificationMethod = GetUserVerificationMethod(securityKeyInfo, userVerification);
            return Authenticate(challenge, rpid, allowedCredentials, userVerificationMethod, userPresence !=  UserPresence.Discouraged, extensions);
        }

        private JArray Authenticate(string challenge, string rpid, JArray allowedCredentials = null, UserVerificationMethod userVeritifcationMethod = null, bool userPresence = true, JObject extensions = null)
        {
            var clientDataJson = CreateClientDataJson(challenge, rpid, "webauthn.get");
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

            var responses = new JArray();
            var response = _ctap.GetAssertion(rpid, clientDataHash, allowList?.EncodeToBytes(), extensionsCbor?.EncodeToBytes(), options?.EncodeToBytes(), pinAuth, pinProtocol);
            var responseCbor = response.ToCborObject();
            responses.Add(CreateAuthenticationResultJson(responseCbor, clientDataJson));

            while (responseCbor.ContainsKey(5) && responseCbor[5].AsInt32() > 0)
            {
                response = _ctap.GetNextAssertion();
                responseCbor = response.ToCborObject();
                responses.Add(CreateAuthenticationResultJson(responseCbor, clientDataJson));
            }

            return responses;
        }
        #endregion

        /// <summary>
        /// Retrieves information about the connected security key, including supported FIDO versions, extensions,
        /// algorithms, and key options.
        /// </summary>
        /// <remarks>If the security key supports multiple FIDO versions, all supported versions are
        /// included in the result. The method also identifies supported extensions and algorithms, and provides default
        /// values if specific information is not available. The returned options indicate the capabilities of the
        /// security key, such as user presence, user verification, resident key support, and client PIN
        /// availability.</remarks>
        /// <returns>A SecurityKeyInfo object that contains details about the supported FIDO versions, extensions, algorithms,
        /// and options for the security key.</returns>
        public SecurityKeyInfo GetSecurityKeyInfo()
        {
            var securityKeyInfoJson = JObject.Parse(_ctap.GetInfo().ToCborObject().ToJSONString());
            var supportedFidoVersions = new List<FidoVersions>();

            if (securityKeyInfoJson.ContainsKey("1"))
            {
                var versions = securityKeyInfoJson["1"] as JArray;
                foreach (string version in versions.Select(v => (string)v))
                {
                    if (version == "FIDO_2_0")
                    {
                        supportedFidoVersions.Add(FidoVersions.FIDO_2_0);
                    }
                    else if (version == "FIDO_2_1")
                    {
                        supportedFidoVersions.Add(FidoVersions.FIDO_2_1);
                    }
                }
            }
            else
            {
                supportedFidoVersions.Add(FidoVersions.FIDO_2_0);
            }

            var supportedExtensions = new List<FidoExtensions>();
            if (securityKeyInfoJson.ContainsKey("2"))
            {
                var extensions = securityKeyInfoJson["2"] as JArray;
                foreach (string extension in extensions.Select(v => (string)v))
                {
                    if (extension == "hmac-secret")
                    {
                        supportedExtensions.Add(FidoExtensions.HMACSecret);
                    }
                    else if (extension == "credProtect")
                    {
                        supportedExtensions.Add(FidoExtensions.CredentialProtectionPolicy);
                    }
                }
            }

            var supportedAlgorithms = new List<Algorithms>();
            if (securityKeyInfoJson.ContainsKey("10"))
            {
                var algorithms = securityKeyInfoJson["10"] as JArray;
                foreach (var algorithm in algorithms)
                {
                    supportedAlgorithms.Add((Algorithms)(int)algorithm["alg"]);
                }
            }
            else
            {
                supportedAlgorithms.Add(Algorithms.ES256);
            }

            var option = new JObject();
            if (securityKeyInfoJson.ContainsKey("4"))
            {
                option = securityKeyInfoJson["4"] as JObject;
            }
            return new SecurityKeyInfo(supportedFidoVersions, supportedExtensions, supportedAlgorithms, 
                option.ContainsKey("up") && (bool)option["up"],
                option.ContainsKey("uv") && (bool)option["uv"],
                option.ContainsKey("clientPin"),
                option.ContainsKey("clientPin") && (bool)option["clientPin"],
                option.ContainsKey("rk") && (bool)option["rk"],
                securityKeyInfoJson);
        }

        /// <summary>
        /// Retrieves the number of remaining attempts allowed for entering the correct PIN on the authenticator.
        /// </summary>
        /// <remarks>Call this method only after the authenticator has been properly initialized. The
        /// returned value can be used to inform users of the number of attempts left before the authenticator is
        /// locked.</remarks>
        /// <returns>The number of remaining PIN entry attempts as an integer.</returns>
        /// <exception cref="Exception">Thrown if the response from the authenticator does not contain the expected data.</exception>
        public int GetPinRetries()
        {
            var ctapResponse = _ctap.GetPinRetries().ToCborObject();
            if (!ctapResponse.ContainsKey(3))
            {
                throw new Exception("Invalid response from Authenticator");
            }
            return ctapResponse[3].AsInt32();
        }

        /// <summary>
        /// Retrieves a secure PIN token for authentication using the specified PIN and protocol version.
        /// </summary>
        /// <remarks>The returned PIN token is derived from the provided PIN and protocol version. Ensure
        /// that the PIN meets any security requirements enforced by the authentication system. The method performs
        /// cryptographic operations to protect the PIN during the token generation process.</remarks>
        /// <param name="pin">The PIN value used to generate the authentication token. This parameter must not be null or empty.</param>
        /// <param name="pinProtocol">The protocol version to use when generating the PIN token. The default is 1.</param>
        /// <returns>A byte array containing the decrypted PIN token that can be used for authentication purposes.</returns>
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

        /// <summary>
        /// Sets a new PIN for user authentication, enforcing security policy requirements.
        /// </summary>
        /// <remarks>The PIN is encrypted using a key agreement secret before being sent to the
        /// authentication system. This method updates the authentication credentials with the new PIN.</remarks>
        /// <param name="pin">The new PIN to set. Must be at least 4 characters in length and no more than 255 bytes when encoded in
        /// UTF-8.</param>
        /// <exception cref="CtapException">Thrown if the specified PIN is shorter than 4 characters or exceeds 255 bytes in length.</exception>
        public void SetPin(string pin)
        {
            if (_keyAgreement == null)
            {
                _keyAgreement = GetKeyAgreement();
            }

            if (pin.Length < 4)
            {
                throw new CtapException(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION, "PIN must be at least 4 characters long!");
            }

            var newPinBytes = Encoding.UTF8.GetBytes(pin);
            if (newPinBytes.Length > 255)
            {
                throw new CtapException(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION, "The PIN is too long!");
            }

            var newPinEnc = Utilities.Encrypt(newPinBytes, _keyAgreement.Secret, new byte[16], PaddingMode.Zeros);

            var hmac = new HMACSHA256(_keyAgreement.Secret);
            var pinAuth = hmac.ComputeHash(newPinEnc).Take(16).ToArray();

            _ctap.SetPin(newPinEnc, _keyAgreement.PlatfromKeyAgreement, pinAuth, 1);
        }

        /// <summary>
        /// Changes the user's PIN to a new value after validating the current PIN and ensuring the new PIN meets length
        /// requirements.
        /// </summary>
        /// <remarks>A key agreement must be established before calling this method. Ensure that the new
        /// PIN adheres to the specified length constraints.</remarks>
        /// <param name="oldPin">The current PIN. This value must match the existing PIN to authorize the change.</param>
        /// <param name="newPin">The new PIN to set. The value must be at least 4 characters and no more than 255 bytes in UTF-8 encoding.</param>
        /// <exception cref="CtapException">Thrown if the new PIN does not meet the length requirements or if the old PIN is invalid.</exception>
        public void ChangePin(string oldPin, string newPin)
        {
            if (_keyAgreement == null)
            {
                _keyAgreement = GetKeyAgreement();
            }

            if (newPin.Length < 4)
            {
                throw new CtapException(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION, "PIN must be at least 4 characters long!");
            }

            var newPinBytes = Encoding.UTF8.GetBytes(newPin);
            if (newPinBytes.Length > 255)
            {
                throw new CtapException(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION, "The PIN is too long!");
            }

            var newPinEnc = Utilities.Encrypt(newPinBytes, _keyAgreement.Secret, new byte[16], PaddingMode.Zeros);

            byte[] pinHash = Utilities.ComputeSha256(Encoding.UTF8.GetBytes(oldPin));
            byte[] pinHashHalf = new byte[16];
            Array.Copy(pinHash, pinHashHalf, 16);
            var pinHashEnc = Utilities.Encrypt(pinHashHalf, _keyAgreement.Secret, new byte[16]);

            var pinAuthData = new byte[pinHashEnc.Length + newPinEnc.Length];
            Array.Copy(newPinEnc, 0, pinAuthData, 0, newPinEnc.Length);
            Array.Copy(pinHashEnc, 0, pinAuthData, newPinEnc.Length, pinHashEnc.Length);
            var hmac = new HMACSHA256(_keyAgreement.Secret);
            var pinAuth = hmac.ComputeHash(pinAuthData).Take(16).ToArray();

            _ctap.ChangePin(pinHashEnc, newPinEnc, _keyAgreement.PlatfromKeyAgreement, pinAuth, 1);
        }

        /// <summary>
        /// Resets the security key to its default state.
        /// </summary>
        /// <remarks>Call this method to reinitialize the security key, clearing any previous
        /// configuration or state. This is typically used before setting new security parameters to ensure a clean
        /// starting point.</remarks>
        public void ResetSecurityKey()
        {
            _ctap.Reset();
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

        private static JObject CreateClientDataJson(string challenge, string rpid, string type)
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

        private UserVerificationMethod GetUserVerificationMethod(SecurityKeyInfo securityKeyInfo, UserVerification userVerification)
        {
            if (userVerification == UserVerification.Required && !securityKeyInfo.SupportsBuildInUserVerification && !securityKeyInfo.SupportsClientPinVerification)
            {
                throw new Exception("User verification is required but the authenticator doesn't support any user verification method!");
            }
            else if (userVerification == UserVerification.Preferred && !securityKeyInfo.SupportsBuildInUserVerification && !securityKeyInfo.SupportsClientPinVerification)
            {
                userVerification = UserVerification.Discouraged;
            }

            var userVerificationMethod = new UserVerificationMethod(UserVerificationType.None);
            if (userVerification == UserVerification.Required || userVerification == UserVerification.Preferred)
            {
                
                if (securityKeyInfo.SupportsBuildInUserVerification)
                {
                    return new UserVerificationMethod(UserVerificationType.BuiltIn);
                }
                else
                {
                    if (_userActionCallback is null)
                    {
                        throw new Exception("No GetPin callback is passed!");
                    }

                    string pin;
                    if (!securityKeyInfo.ClientPinIsSet)
                    {
                        if (_userActionCallback != null)
                        {
                            pin = _userActionCallback(new UserActionCallbackArgs(UserActionCallbackActions.SetPin)).Pin;
                            SetPin(pin);
                        }
                        else
                        {
                            throw new Exception("Security Key pin is not set");
                        }
                    }
                    else
                    {
                        if (GetPinRetries() <= 0)
                        {
                            throw new CtapException(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED, "Security Key PIN is blocked!");
                        }

                        pin = _userActionCallback(new UserActionCallbackArgs(UserActionCallbackActions.GetPin)).Pin;
                    }

                    byte[] pinToken;
                    while (true)
                    {
                        try
                        {
                            pinToken = GetPinToken(pin);
                            break;
                        }
                        catch (CtapException ex)
                        {
                            if (ex.StatusCode == CtapStatusCode.CTAP2_ERR_PIN_INVALID)
                            {
                                _keyAgreement = null;
                                pin = _userActionCallback(new UserActionCallbackArgs(UserActionCallbackActions.GetPinWithWrongPinMessage)).Pin;
                                continue;
                            }
                            throw new CtapException(ex.StatusCode, ex.Message);
                        }
                    }

                    return new UserVerificationMethod(UserVerificationType.ClientPin, pinToken);
                }
                
            }
            return new UserVerificationMethod(UserVerificationType.None);
        }

        private void CheckUserPresenceSatisfaction(SecurityKeyInfo securityKeyInfo, UserPresence userPresence)
        {
            if (_device.DeviceInfo.Transport != Transports.NFC && userPresence == UserPresence.Required && !securityKeyInfo.SupportesUserPresence)
            {
                throw new Exception("User presence is required but the authenticator doesn't support it!");
            }
        }

        private static void CheckSupportedAlgorithms(SecurityKeyInfo securityKeyInfo, JArray pubKeyCredParams)
        {
            var supportedAlgorithms = securityKeyInfo.SupportedAlgorithms;
            if (supportedAlgorithms.Any())
            {
                bool supportedAlgorithmFound = false;
                foreach (var algorithm in pubKeyCredParams)
                {
                    if (supportedAlgorithms.Contains((Algorithms)(int)algorithm["alg"]))
                    {
                        supportedAlgorithmFound = true;
                        break;
                    }
                }
                if (!supportedAlgorithmFound)
                {
                    throw new Exception("None of the requested algorithms are supported by the authenticator!");
                }
            }
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
