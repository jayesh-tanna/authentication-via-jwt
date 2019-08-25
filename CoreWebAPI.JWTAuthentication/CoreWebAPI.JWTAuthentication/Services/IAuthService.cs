using System.Collections.Generic;
using System.Security.Claims;

namespace CoreWebAPI.JWTAuthentication.Services
{
    public interface IAuthService
    {
        bool IsTokenValid(string token);

        string GenerateToken(IEnumerable<Claim> claims);

        IEnumerable<Claim> GetTokenClaims(string token);
    }
}