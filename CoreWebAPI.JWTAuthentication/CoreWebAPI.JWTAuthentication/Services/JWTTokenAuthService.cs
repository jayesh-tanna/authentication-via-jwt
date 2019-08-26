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
        private string SecurityAlgorithm { get; }
        private int ExpiryInMinutes { get; }
        private string SecretKey { get; }
        private readonly IConfiguration configuration;

        public JWTTokenAuthService(IConfiguration configuration)
        {
            this.configuration = configuration;
            SecretKey = this.configuration["JWTTokenService:SecretKey"];
            ExpiryInMinutes = Convert.ToInt32(this.configuration["JWTTokenService:ExpiryInMinutes"]);
            SecurityAlgorithm = this.configuration["JWTTokenService:SecurityAlgorithm"];
        }

        public bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty.");

            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public string GenerateToken(IEnumerable<Claim> claims)
        {
            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(ExpiryInMinutes),
                SigningCredentials = new SigningCredentials(GetSymmetricSecurityKey(), SecurityAlgorithm)
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            string token = jwtSecurityTokenHandler.WriteToken(securityToken);

            return token;
        }

        public IEnumerable<Claim> GetTokenClaims(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Invalid token");

            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
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