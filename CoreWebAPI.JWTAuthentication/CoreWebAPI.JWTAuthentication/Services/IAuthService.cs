using System.Collections.Generic;
using System.Security.Claims;

namespace CoreWebAPI.JWTAuthentication.Services
{
    public interface IAuthService
    {
        string GenerateToken(IEnumerable<Claim> claims);
    }
}