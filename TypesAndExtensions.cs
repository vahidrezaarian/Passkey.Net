using CtapDotNet.Transports;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace PasskeyDotNet
{
    /// <summary>
    /// Specifies the required level of user presence in a given context.
    /// </summary>
    /// <remarks>This enumeration defines three levels of user presence: Discouraged, Preferred, and Required.
    /// Each value indicates the importance of user presence for the operation or feature being implemented. Use this
    /// enumeration to communicate whether user presence is optional, recommended, or mandatory for a particular action
    /// or workflow.</remarks>
    public enum UserPresence
    {
        /// <summary>
        /// User presence is not required and may be bypassed if the device supports it.
        /// </summary>
        Discouraged,
        /// <summary>
        /// User presence is recommended but not strictly required. The device may allow bypassing user presence, but it is encouraged to have it for better security.
        /// </summary>
        Preferred,
        /// <summary>
        /// User presence is mandatory and must be verified for the operation to proceed. The device must enforce user presence and cannot bypass it.
        /// </summary>
        Required
    }

    /// <summary>
    /// Specifies the level of user verification required for an operation.
    /// </summary>
    /// <remarks>This enumeration defines three levels of user verification: Discouraged, Preferred, and
    /// Required. The choice of level can influence the security and user experience of the application.</remarks>
    public enum UserVerification
    {
        /// <summary>
        /// User verification is not required and may be bypassed if the device supports it.
        /// </summary>
        Discouraged,
        /// <summary>
        /// User verification is recommended but not strictly required. The device may allow bypassing user verification, but it is encouraged to have it for better security.
        /// </summary>
        Preferred,
        /// <summary>
        /// User verification is mandatory and must be verified for the operation to proceed. The device must enforce user verification and cannot bypass it.
        /// </summary>
        Required
    }

    /// <summary>
    /// Specifies the available methods for verifying a user's identity.
    /// </summary>
    /// <remarks>This enumeration defines the supported user verification mechanisms, such as built-in
    /// authenticators, client PINs, or the absence of verification. The selected value determines how user presence or
    /// identity is confirmed during authentication processes.</remarks>
    public enum UserVerificationType
    {
        /// <summary>
        /// User verification is performed using built-in authenticators, such as biometric sensors (fingerprint, facial recognition) or other hardware-based methods.
        /// </summary>
        BuiltIn,
        /// <summary>
        /// User verification is performed using a client PIN, which is a numeric code set by the user. The device will prompt the user to enter their PIN for verification.
        /// </summary>
        ClientPin,
        /// <summary>
        /// No user verification is performed. This option may be used in scenarios where user presence is not required or when the device does not support any verification methods.
        /// </summary>
        None
    }

    /// <summary>
    /// Specifies the supported versions of the FIDO (Fast IDentity Online) protocol.
    /// </summary>
    /// <remarks>Use this enumeration to indicate which version of the FIDO protocol is being used in
    /// authentication operations. Selecting the correct version ensures compatibility with FIDO-compliant devices and
    /// services.</remarks>
    public enum FidoVersions
    {
        /// <summary>
        /// Represents the FIDO 2.0 authentication standard, which enhances security for online authentication by
        /// enabling passwordless login.
        /// </summary>
        /// <remarks>This standard is designed to provide a secure and user-friendly authentication
        /// experience, leveraging public key cryptography to protect user credentials.</remarks>
        FIDO_2_0,
        /// <summary>
        /// Represents the FIDO 2.1 authentication standard, which enhances security for online authentication
        /// processes.
        /// </summary>
        /// <remarks>This standard includes improvements over previous versions, focusing on user privacy
        /// and security. It is designed to work with various devices and platforms, ensuring a seamless authentication
        /// experience.</remarks>
        FIDO_2_1,
    }

    /// <summary>
    /// Specifies the cryptographic algorithms supported for digital signatures.
    /// </summary>
    /// <remarks>This enumeration includes commonly used algorithms such as ES256, ES384, ES512, RS256, RS384,
    /// RS512, and EdDSA. These algorithms are typically used in security protocols to sign and verify data, ensuring
    /// data integrity and authenticity. Each member is associated with a unique integer value that may correspond to
    /// standardized identifiers in cryptographic specifications.</remarks>
    public enum Algorithms
    {
        /// <summary>
        /// Represents the ES256 algorithm identifier, which is used for ECDSA signatures with the P-256 curve and
        /// SHA-256 hash function.
        /// </summary>
        ES256 = -7,
        /// <summary>
        /// Represents the ES384 elliptic curve digital signature algorithm, which uses the P-384 curve and SHA-384 hash
        /// function.
        /// </summary>
        /// <remarks>This value is typically used to specify the ES384 algorithm in cryptographic
        /// operations such as signing and verifying digital signatures. ES384 is defined in RFC 7518 and is commonly
        /// used in JSON Web Token (JWT) and other security protocols.</remarks>
        ES384 = -35,
        /// <summary>
        /// Represents the ES512 cryptographic algorithm identifier, which specifies the use of the ECDSA algorithm with
        /// the P-521 curve and SHA-512 hash function.
        /// </summary>
        ES512 = -36,
        /// <summary>
        /// Represents the identifier for the RS256 cryptographic algorithm, which uses RSA with SHA-256.
        /// </summary>
        /// <remarks>This value is typically used when specifying the algorithm for JSON Web Tokens (JWT)
        /// or other cryptographic operations that require RS256. The numeric value corresponds to the standard
        /// identifier for RS256 as defined in relevant cryptographic specifications.</remarks>
        RS256 = -257,
        /// <summary>
        /// Represents the RS384 cryptographic algorithm identifier.
        /// </summary>
        RS384 = -258,
        /// <summary>
        /// Represents the RS512 signing algorithm, which uses the SHA-512 hash function and RSA encryption.
        /// </summary>
        RS512 = -259,
        /// <summary>
        /// Represents the Edwards-Curve Digital Signature Algorithm (EdDSA) cryptographic algorithm.
        /// </summary>
        EdDSA = -8
    }

    /// <summary>
    /// Specifies the available extensions that can be used in FIDO authentication operations.
    /// </summary>
    /// <remarks>Use this enumeration to indicate which FIDO extensions are supported or requested during
    /// authentication or credential creation. Extensions such as HMAC secret and credential protection policy enable
    /// additional features or security requirements in FIDO workflows.</remarks>
    public enum FidoExtensions
    {
        /// <summary>
        /// Represents the HMAC secret value used for cryptographic operations.
        /// </summary>
        HMACSecret = 1,
        /// <summary>
        /// Specifies that the application should use a credential protection policy when handling credentials.
        /// </summary>
        /// <remarks>This enumeration value indicates that credential storage and retrieval may be subject
        /// to additional security requirements, such as enhanced protection or restricted access, depending on the
        /// platform and configuration. Use this value to enforce stricter credential handling policies in scenarios
        /// where sensitive information must be safeguarded.</remarks>
        CredentialProtectionPolicy = 2,
    }

    /// <summary>
    /// Specifies the set of actions that can be performed for user PIN management and security key interactions in
    /// authentication workflows.
    /// </summary>
    /// <remarks>Use this enumeration to indicate the required user action during authentication or credential
    /// management processes, such as retrieving, setting, or changing a PIN, or prompting the user to touch a security
    /// key. Some actions also support scenarios where an incorrect PIN has been entered, allowing for appropriate user
    /// feedback.</remarks>
    public enum UserActionCallbackActions
    {
        /// <summary>
        /// Asks for the current Security Key PIN.
        /// </summary>
        /// <remarks>This property retrieves the PIN that is used for authentication purposes. Ensure that
        /// the PIN is kept secure and not exposed in logs or error messages.</remarks>
        GetPin,
        /// <summary>
        /// Asks for the current Security Key PIN. It also informs you that the previous entered PIN was wrong, so you can show the wrong PIN message.
        /// </summary>
        /// <remarks>Use this property to provide clear and helpful feedback to users when a PIN entry
        /// attempt fails. Ensure that the message guides users on how to proceed or correct their input.</remarks>
        GetPinWithWrongPinMessage,
        /// <summary>
        /// Gets a PIN to set on the Security Key when no PIN is set.
        /// </summary>
        /// <remarks>The PIN must be a numeric value containing between 4 and 8 digits. Supplying a PIN
        /// that does not meet these criteria may result in an exception. Ensure that the chosen PIN complies with your
        /// organization's security policies.</remarks>
        SetPin,
        /// <summary>
        /// Gets the old and a new PIN to use for calling the ChangePin method, which allows users to update their existing PIN to a new one.
        /// </summary>
        /// <remarks>This method requires the current PIN to be verified before allowing the change.
        /// Ensure that the new PIN meets the security requirements, such as length and complexity.</remarks>
        ChangePin,
        /// <summary>
        /// Gets the old and a new PIN to use for calling the ChangePin method, which allows users to update their existing PIN to a new one. It also informs you that the previous entered PIN was wrong, so you can show the wrong PIN message.
        /// </summary>
        ChangePinWithWrongPinMessage,
        /// <summary>
        /// Informs you that a user interaction is required on the Security Key.
        /// </summary>
        TouchSecurityKey
    }

    /// <summary>
    /// Represents the arguments for a user action callback, containing the specific action that needs to be performed during authentication or credential management processes.
    /// </summary>
    public class UserActionCallbackArgs
    {
        /// <summary>
        /// The action to be performed, which can be one of the following: GetPin, GetPinWithWrongPinMessage, SetPin, ChangePin, ChangePinWithWrongPinMessage, or TouchSecurityKey. This property indicates the required user interaction for the current step in the authentication or credential management workflow.
        /// </summary>
        public UserActionCallbackActions Action;

        /// <summary>
        /// Creates a new instance of the UserActionCallbackArgs class with the specified action.
        /// </summary>
        /// <param name="action"></param>
        public UserActionCallbackArgs(UserActionCallbackActions action)
        {
            Action = action;
        }
    }

    /// <summary>
    /// Represents the result of a user action callback, containing the necessary information such as the current PIN and an optional new PIN for operations that involve setting or changing a PIN. This class is used to encapsulate the data returned from user interactions during authentication or credential management processes, allowing for structured handling of user input and subsequent actions based on that input.
    /// </summary>
    public class UserActionCallbackResult
    {
        /// <summary>
        /// The current PIN entered by the user, which is required for operations such as authentication or verifying the existing PIN before allowing a change. This property should be securely handled to prevent exposure of sensitive information.
        /// </summary>
        public string Pin;
        /// <summary>
        /// The new PIN entered by the user, which is required for operations that involve setting a new PIN or changing an existing PIN. This property is optional and should only be provided when the action involves setting or changing a PIN. Ensure that the new PIN meets security requirements and is handled securely to prevent unauthorized access.
        /// </summary>
        public string NewPin;

        /// <summary>
        /// Creates a new instance of the UserActionCallbackResult class with the specified current PIN and an optional new PIN.
        /// </summary>
        /// <param name="pin"></param>
        /// <param name="newPin"></param>
        public UserActionCallbackResult(string pin, string newPin = null)
        {
            Pin = pin;
            NewPin = newPin;
        }
    }

    /// <summary>
    /// Represents the information about a security key, including supported FIDO versions, extensions, algorithms, and various capabilities related to user presence, verification methods, and resident key storage. This class encapsulates the details of a security key's features and capabilities, allowing for easy access and management of this information in authentication workflows or when interacting with security keys in general.
    /// </summary>
    public class SecurityKeyInfo
    {
        /// <summary>
        /// The list of supported FIDO versions by the security key, such as FIDO 2.0 and FIDO 2.1. This information is crucial for determining compatibility with different authentication protocols and ensuring that the security key can be used effectively in various scenarios.
        /// </summary>
        public List<FidoVersions> SupportedFidoVersions;
        /// <summary>
        /// The list of supported FIDO extensions by the security key, such as HMAC secret and credential protection policy. This information helps to identify the additional features and capabilities of the security key, allowing for enhanced functionality in authentication processes and better security measures when handling credentials.
        /// </summary>
        public List<FidoExtensions> SupportedExtensions;
        /// <summary>
        /// The list of supported cryptographic algorithms for digital signatures by the security key, such as ES256, ES384, ES512, RS256, RS384, RS512, and EdDSA. This information is essential for determining which algorithms can be used for signing and verifying data during authentication processes, ensuring that the security key can meet the specific requirements of different applications and services.
        /// </summary>
        public List<Algorithms> SupportedAlgorithms;
        /// <summary>
        /// Declares if the security key supports user presence, which is a crucial aspect of authentication processes. User presence indicates whether the security key can detect and verify the physical presence of the user during authentication, providing an additional layer of security by ensuring that the authentication process is initiated by a legitimate user. This property helps to determine the level of security and user interaction required when using the security key for authentication purposes.
        /// </summary>
        public bool SupportesUserPresence;
        /// <summary>
        /// Declares if the security key supports built-in user verification methods, such as biometric sensors (fingerprint, facial recognition) or other hardware-based methods. This property indicates whether the security key can perform user verification using its built-in capabilities, which can enhance security by providing a more seamless and user-friendly authentication experience. If this property is true, it means that the security key can verify the user's identity without relying on external factors, such as a client PIN, making it a more convenient option for users while still maintaining strong security measures.
        /// </summary>
        public bool SupportsBuildInUserVerification;
        /// <summary>
        /// Declares if the security key supports client PIN verification, which is a method of user verification that relies on a numeric code set by the user. This property indicates whether the security key can prompt the user to enter their PIN for verification during authentication processes. If this property is true, it means that the security key can use client PINs as a means of verifying the user's identity, providing an additional layer of security for authentication operations. The presence of this feature allows for greater flexibility in authentication methods, catering to users who may prefer or require PIN-based verification over built-in biometric options.
        /// </summary>
        public bool SupportsClientPinVerification;
        /// <summary>
        /// Declares if a client PIN is set on the security key, which indicates whether the user has configured a numeric code for authentication purposes. This property is important for determining the security posture of the security key, as having a client PIN set can provide an additional layer of protection against unauthorized access. If this property is true, it means that the user has set a client PIN on the security key, which can be used for verification during authentication processes. Conversely, if this property is false, it indicates that no client PIN is configured, and the security key may rely solely on other verification methods, such as built-in user verification or user presence, for authentication.
        /// </summary>
        public bool ClientPinIsSet;
        /// <summary>
        /// Declares if the security key supports resident key storage, which is a feature that allows the security key to store credentials directly on the device. This property indicates whether the security key can manage and store user credentials locally, providing a more convenient and secure authentication experience. If this property is true, it means that the security key can support resident keys, which can be used for passwordless authentication and other advanced features. Resident key storage can enhance security by keeping credentials on the device, reducing the risk of credential theft or compromise during transmission.
        /// </summary>
        public bool SupportsResidentKeyStorage;
        /// <summary>
        /// Represents the raw JSON object containing all the information about the security key, including supported FIDO versions, extensions, algorithms, and various capabilities. This property allows for easy access to the complete set of information about the security key in a structured format, enabling developers to utilize this data for various purposes, such as debugging, logging, or further processing in authentication workflows. The JSON object can be used to extract specific details or to provide a comprehensive overview of the security key's features and capabilities when needed.
        /// </summary>
        public JObject JsonObject;

        /// <summary>
        /// Creates a new instance of the SecurityKeyInfo class with the specified supported FIDO versions, extensions, algorithms, and various capabilities related to user presence, verification methods, and resident key storage. This constructor initializes all the properties of the SecurityKeyInfo class, allowing for the creation of a comprehensive representation of a security key's features and capabilities based on the provided information. The JSON object parameter allows for storing the raw data in a structured format for easy access and further processing as needed.
        /// </summary>
        /// <param name="supportedFidoVersions"></param>
        /// <param name="supportedExtensions"></param>
        /// <param name="supportedAlgorithms"></param>
        /// <param name="supportesUserPresence"></param>
        /// <param name="supportsBuildInUserVerification"></param>
        /// <param name="supportsClientPinVerification"></param>
        /// <param name="clientPinIsSet"></param>
        /// <param name="supportsResidentKeyStorage"></param>
        /// <param name="jsonObject"></param>
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

        /// <summary>
        /// Returnes the raw JSON object as a string representation, which contains all the information about the security key, including supported FIDO versions, extensions, algorithms, and various capabilities. This method provides a convenient way to access the complete set of information about the security key in a human-readable format, allowing for easy debugging, logging, or further processing in authentication workflows. The JSON string can be used to extract specific details or to provide a comprehensive overview of the security key's features and capabilities when needed.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return JsonObject.ToString();
        }
    }

    /// <summary>
    /// Represents the user verification method, including the type of verification (built-in, client PIN, or none), the PIN token used for client PIN verification, and the protocol version for the PIN. This class encapsulates the details of the user verification method being used in authentication processes, allowing for structured handling of different verification mechanisms based on the capabilities of the security key and the requirements of the authentication workflow. The PIN token is typically used for client PIN verification and should be securely handled to prevent unauthorized access. The protocol version indicates which version of the PIN protocol is being used, ensuring compatibility with different security keys and authentication scenarios.
    /// </summary>
    public class UserVerificationMethod
    {
        /// <summary>
        /// Represents the type of user verification method being used, which can be one of the following: BuiltIn, ClientPin, or None. This property indicates how the user's identity is being verified during authentication processes, allowing for different levels of security and user interaction based on the capabilities of the security key and the requirements of the authentication workflow. Built-in verification typically involves biometric sensors or hardware-based methods, while client PIN verification relies on a numeric code set by the user. The None option indicates that no user verification is being performed, which may be suitable for certain scenarios where user presence is not required or when the device does not support any verification methods.
        /// </summary>
        public UserVerificationType Type;
        /// <summary>
        /// The PIN token used for client PIN verification, which is a byte array that contains the necessary information for verifying the user's PIN during authentication processes. This property is relevant when the user verification type is set to ClientPin, and it should be securely handled to prevent unauthorized access. The PIN token typically includes encrypted data that allows the security key to verify the user's PIN without exposing the actual PIN value, enhancing security while still enabling effective user verification.
        /// </summary>
        public byte[] PinToken;
        /// <summary>
        /// The protocol version for the PIN, which is an integer that indicates which version of the PIN protocol is being used for client PIN verification. This property is relevant when the user verification type is set to ClientPin, and it ensures compatibility with different security keys and authentication scenarios. The protocol version may affect how the PIN token is generated and processed during authentication, so it is important to specify the correct version based on the capabilities of the security key and the requirements of the authentication workflow.
        /// </summary>
        public int PinProtocol;

        /// <summary>
        /// Creates a new instance of the UserVerificationMethod class with the specified type of verification, PIN token, and protocol version for the PIN. This constructor initializes all the properties of the UserVerificationMethod class, allowing for the creation of a comprehensive representation of the user verification method being used in authentication processes. The PIN token is optional and should only be provided when the type is set to ClientPin, while the protocol version defaults to 1 if not specified.
        /// </summary>
        /// <param name="type"></param>
        /// <param name="pinToken"></param>
        /// <param name="pinProtocol"></param>
        public UserVerificationMethod(UserVerificationType type, byte[] pinToken = null, int pinProtocol = 1)
        {
            Type = type;
            PinToken = pinToken;
            PinProtocol = pinProtocol;
        }
    }

    /// <summary>
    /// Represents a set of extension methods for converting string data into JSON objects and arrays using the Newtonsoft.Json library. These extension methods provide convenient ways to parse JSON-formatted strings into structured JObject and JArray instances, allowing for easy manipulation and access to JSON data in C#. The ToJsonObject method parses a string into a JObject, while the ToJsonArrayObject method parses a string into a JArray, enabling developers to work with JSON data in a more intuitive and efficient manner within their applications.
    /// </summary>
    public static partial class Extensions
    {
        /// <summary>
        /// Converts a JSON-formatted string into a JObject, which is a structured representation of the JSON data that allows for easy access and manipulation of its properties and values. This extension method uses the JObject.Parse method from the Newtonsoft.Json library to parse the input string and return a JObject instance. It is useful for scenarios where you need to work with JSON data in a structured way, such as when processing API responses or handling configuration data in JSON format.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static JObject ToJsonObject(this string data)
        {
            return JObject.Parse(data);
        }

        /// <summary>
        ///  Converts a JSON-formatted string into a JArray, which is a structured representation of a JSON array that allows for easy access and manipulation of its elements. This extension method uses the JArray.Parse method from the Newtonsoft.Json library to parse the input string and return a JArray instance. It is useful for scenarios where you need to work with JSON data that is structured as an array, such as when processing lists of items or handling API responses that return arrays in JSON format.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static JArray ToJsonArrayObject(this string data)
        {
            return JArray.Parse(data);
        }
    }
}
