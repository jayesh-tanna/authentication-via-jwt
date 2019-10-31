using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CoreWebAPI.JWTAuthentication.Services
{
    public class JWTAuthService : IAuthService
    {
        private int ExpiryInMinutes { get; }
        private string SecretKey { get; }
        private readonly IConfiguration configuration;

        public JWTAuthService(IConfiguration configuration)
        {
            this.configuration = configuration;
            SecretKey = this.configuration["JWTService:SecretKey"];
            ExpiryInMinutes = Convert.ToInt32(this.configuration["JWTService:ExpiryInMinutes"]);
        }

        public string GenerateToken(IEnumerable<Claim> claims)
        {
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(ExpiryInMinutes),
                SigningCredentials = new SigningCredentials(GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            string token = tokenHandler.WriteToken(securityToken);

            return token;
        }

        private SecurityKey GetSymmetricSecurityKey()
        {
            byte[] symmetricKey = Encoding.ASCII.GetBytes(SecretKey);
            return new SymmetricSecurityKey(symmetricKey);
        }
    }
}