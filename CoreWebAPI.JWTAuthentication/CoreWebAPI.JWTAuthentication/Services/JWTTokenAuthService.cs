using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace CoreWebAPI.JWTAuthentication.Services
{
    public class JWTTokenAuthService : IAuthService
    {
        private int ExpiryInMinutes { get; }
        private string SecretKey { get; }
        private readonly IConfiguration configuration;

        public JWTTokenAuthService(IConfiguration configuration)
        {
            this.configuration = configuration;
            SecretKey = this.configuration["JWTTokenService:SecretKey"];
            ExpiryInMinutes = Convert.ToInt32(this.configuration["JWTTokenService:ExpiryInMinutes"]);
        }

        public bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            TokenValidationParameters parameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = tokenHandler.ValidateToken(token, parameters, out SecurityToken validatedToken);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
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

        public IEnumerable<Claim> GetTokenClaims(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Invalid token");

            TokenValidationParameters parameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = tokenHandler.ValidateToken(token, parameters, out SecurityToken validatedToken);
                return tokenValid.Claims;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private SecurityKey GetSymmetricSecurityKey()
        {
            byte[] symmetricKey = Convert.FromBase64String(SecretKey);
            return new SymmetricSecurityKey(symmetricKey);
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = GetSymmetricSecurityKey()
            };
        }
    }
}