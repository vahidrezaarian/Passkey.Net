using CtapDotNet.Transports;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace PasskeyDotNet
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

    public enum FidoVersions
    {
        FIDO_2_0,
        FIDO_2_1,
    }

    public enum Algorithms
    {
        ES256 = -7,
        ES384 = -35,
        ES512 = -36,
        RS256 = -257,
        RS384 = -258,
        RS512 = -259,
        EdDSA = -8
    }

    public enum FidoExtensions
    {
        HMACSecret = 1,
        CredentialProtectionPolicy = 2,
    }

    public enum UserActionCallbackActions
    {
        GetPin,
        GetPinWithWrongPinMessage,
        SetPin,
        ChangePin,
        ChangePinWithWrongPinMessage,
        TouchSecurityKey
    }

    public class UserActionCallbackArgs
    {
        public UserActionCallbackActions Action;

        public UserActionCallbackArgs(UserActionCallbackActions action)
        {
            Action = action;
        }
    }

    public class UserActionCallbackResult
    {
        public string Pin;
        public string NewPin;

        public UserActionCallbackResult(string pin, string newPin = null)
        {
            Pin = pin;
            NewPin = newPin;
        }
    }

    public class SecurityKeyInfo
    {
        public List<FidoVersions> SupportedFidoVersions;
        public List<FidoExtensions> SupportedExtensions;
        public List<Algorithms> SupportedAlgorithms;
        public bool SupportesUserPresence;
        public bool SupportsBuildInUserVerification;
        public bool SupportsClientPinVerification;
        public bool ClientPinIsSet;
        public bool SupportsResidentKeyStorage;
        public JObject JsonObject;

        public SecurityKeyInfo(List<FidoVersions> supportedFidoVersions, List<FidoExtensions> supportedExtensions, List<Algorithms> supportedAlgorithms, bool supportesUserPresence,
            bool supportsBuildInUserVerification, bool supportsClientPinVerification, bool clientPinIsSet, bool supportsResidentKeyStorage, JObject jsonObject)
        {
            SupportedFidoVersions = supportedFidoVersions;
            SupportedExtensions = supportedExtensions;
            SupportedAlgorithms = supportedAlgorithms;
            SupportesUserPresence = supportesUserPresence;
            SupportsBuildInUserVerification = supportsBuildInUserVerification;
            SupportsClientPinVerification = supportsClientPinVerification;
            ClientPinIsSet = clientPinIsSet;
            SupportsResidentKeyStorage = supportsResidentKeyStorage;
            JsonObject = jsonObject;
        }

        public override string ToString()
        {
            return JsonObject.ToString();
        }
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

    public class StatusChangeEventArgs : EventArgs
    {
        public string Message { get; set; }
        public FidoSecurityKeyDevice Device { get; set; }
    }

    public static partial class Extensions
    {
        public static JObject ToJsonObject(this string data)
        {
            return JObject.Parse(data);
        }

        public static JArray ToJsonArrayObject(this string data)
        {
            return JArray.Parse(data);
        }
    }
}
