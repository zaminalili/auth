using System.Security.Cryptography;
using Auth.Core.Models.Settings;
using Microsoft.Extensions.Options;

namespace Auth.Core.Services;

public class Hasher(IOptions<TokenSettings> options)
{
    private readonly string _pepper = options.Value.Key;
    private readonly HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SHA512;
    private const char Delimiter = ';';
    
    public string HashPbkdf2(string value, int iterations = 200_000)
    {
        var salt = RandomNumberGenerator.GetBytes(32);
        
        string input = value + _pepper;

        using var pbkdf2 = new Rfc2898DeriveBytes(input, salt, iterations, _hashAlgorithmName);
        var hash = pbkdf2.GetBytes(32);

        return $"PBKDF2{Delimiter}{iterations}{Delimiter}{Convert.ToBase64String(salt)}{Delimiter}{Convert.ToBase64String(hash)}";
    }

    public bool VerifyPbkdf2(string value, string hashedValue)
    {
        try
        {
            var parts = hashedValue.Split(Delimiter);
            if (parts is not ["PBKDF2", _, _, _])
                return false;

            var iterations = int.Parse(parts[1]);
            var salt = Convert.FromBase64String(parts[2]);
            var expectedHash = Convert.FromBase64String(parts[3]);

            string input = value + _pepper;

            using var pbkdf2 = new Rfc2898DeriveBytes(input, salt, iterations, _hashAlgorithmName);
            var actualHash = pbkdf2.GetBytes(expectedHash.Length);

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        catch
        {
            return false;
        }
    }
}