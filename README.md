# Passkey.Net
.NET and .NET Framework library for FIDO2 passkey creation and authentication.   

Built on top of [Ctap.Net](https://www.nuget.org/packages/Ctap.Net) for secure USB/NFC authenticator communication.  

Perfect for passwordless auth flows in any .NET app integrating passkeys.

Provides Security Key controlling functions like PIN setting and PIN changing.

## Installation

Install via NuGet:

```bash
dotnet add package Passkey.Net
```

Or in your .csproj:
```XML
<PackageReference Include="Passkey.Net" Version="1.0.0" />
```

The latest version: https://www.nuget.org/packages/Passkey.Net/1.0.0

## How to use
You simply need to look for a FIDO security key device, choose one and create an object of Passkey class using the found device. Then call the passkey related functions for that device.
```C#

foreach (var device in FidoSecurityKeyDevices.AllDevices)
{
    using (var passkey = new Passkey(device, UserActionCallback)) // Make sure the passkey object is disposed when finished
    {
        var registrationResponse = passkey.Create(new JObject()
        {
            ["challenge"] = "pgIfj2fnom8rJdb4_h1gKqDkq-gxHFksI-m2aR5T-PNNycBfENAM4ksEBvoXky6d",
            ["rp"] = new JObject()
            {
                ["id"] = "login.microsoft.com",
                ["name"] = "Microsoft"
            },
            ["user"] = new JObject()
            {
                ["id"] = "T0Y6Ehqp2EfQP0iExdt54DFwdWuaH7qIZbZGpOc92RGnvbXyRPvU-8AOp9r1T7Cebfc3",
                ["name"] = "user@domain.com",
                ["displayName"] = "Vahidreza Arian"
            },
            ["pubKeyCredParams"] = new JArray()
            {
                new JObject()
                {
                    ["type"] = "public-key",
                    ["alg"] = -7
                },
                new JObject()
                {
                    ["type"] = "public-key",
                    ["alg"] = -256
                }
            },
            ["extensions"] = new JObject()
            {
                ["hmacCreateSecret"] = true,
                ["enforceCredentialProtectionPolicy"] = true
            }
        }, UserVerification.Preferred, UserPresence.Required);

        var authenticationResponse = passkey.Authenticate(new JObject()
        {
            ["challenge"] = "pgIfj2fnom8rJdb4_h1gKqDkq-gxHFksI-m2aR5T-PNNycBfENAM4ksEBvoXky6d",
            ["rpId"] = "login.microsoft.com",
            ["extensions"] = new JObject()
            {
                ["hmacGetSecret"] = new JObject()
                {
                    ["salt1"] = "qB3fJ9tL2kP8mR5vN0wY4hC7eD1gK6sU9xZ2nM3rT5pQ8vF0jA"
                }
            }
        }, UserVerification.Required, UserPresence.Required);
    }
}

// This callback makes the library handle the GetPin and SetPin functions along with notifying you of user actio requirement
// You can handle this callback and implement a UI
UserActionCallbackResult UserActionCallback(UserActionCallbackArgs args)
{
    if (args.Action == UserActionCallbackActions.TouchSecurityKey)
    {
        Console.WriteLine("Touch your security key");
        return null;
    }
    else if (args.Action == UserActionCallbackActions.GetPin)
    {
        Console.Write("Enter the Security Key PIN: ");
    }
    else if (args.Action == UserActionCallbackActions.GetPinWithWrongPinMessage)
    {
        Console.WriteLine("Security key pin was wrong!");
        Console.Write("Enter the Security Key PIN: ");
    }
    else if (args.Action == UserActionCallbackActions.SetPin)
    {
        Console.Write("Please set a pin first\n");
        Console.Write("Enter the Security Key PIN: ");
    }

    var pin = new StringBuilder();
    ConsoleKeyInfo key;
    do
    {
        key = Console.ReadKey(true);
        if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
        {
            pin.Append(key.KeyChar);
            Console.Write("*");
        }
        else if (key.Key == ConsoleKey.Backspace && pin.Length > 0)
        {
            pin.Remove(pin.Length - 1, 1);
            Console.Write("\b \b");
        }
    } while (key.Key != ConsoleKey.Enter);
    Console.WriteLine();

    return new UserActionCallbackResult(pin.ToString());
}
```