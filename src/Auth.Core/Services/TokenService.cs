using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Auth.Core.Models.Settings;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Core.Services;

public class TokenService(IOptions<TokenSettings> options)
{
    protected readonly string issuer = options.Value.Issuer;
    protected readonly string audience = options.Value.Audience;
    protected readonly string secretKey = options.Value.Key;
    
    
    public virtual string GenerateAccessToken(string id, string email, string roleName, double expireTimeMinute = 30)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, id),
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Role, roleName),
            new Claim(JwtRegisteredClaimNames.Jti,  Guid.NewGuid().ToString())
        };

        return CreateJwt(claims, DateTime.UtcNow.AddMinutes(expireTimeMinute));
    }
    
    public virtual string GenerateAccessToken(string email, string? jti, double expireTimeMinute = 30)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti,  jti ??  Guid.NewGuid().ToString()),
        };

        return CreateJwt(claims, DateTime.UtcNow.AddMinutes(expireTimeMinute));
    }

    public virtual string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);

        return Convert.ToBase64String(randomNumber);
    }

    public virtual bool ValidateToken(string token, out ClaimsPrincipal principal)
    {
        principal = null!;
        
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            principal = tokenHandler.ValidateToken(token, ValidationParameters, out var validatedToken);

            return validatedToken is JwtSecurityToken;
        }
        catch
        {
            return false;
        }
    }
    
    protected virtual string CreateJwt(Claim[] claims, DateTime expireDate)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

        var tokenDescriptor = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expireDate,
            signingCredentials: credentials);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        return tokenString;
    }
    
    protected virtual TokenValidationParameters ValidationParameters => new()
    {   
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
}