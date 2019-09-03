using CoreWebAPI.JWTAuthentication.Models;
using CoreWebAPI.JWTAuthentication.Services;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;

namespace CoreWebAPI.JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService authService;

        public UserController(IAuthService authService)
        {
            this.authService = authService;
        }

        [Route("login")]
        [HttpPost]
        public IActionResult Post([FromBody]User user)
        {
            if ((user.LoginId == "abc" && user.Password == "abc") || (user.LoginId == "123" && user.Password == "123"))
            {
                var token = authService.GenerateToken(GetClaims(user.LoginId));

                return Ok(token);
            }
            return StatusCode((int)HttpStatusCode.Unauthorized);
        }

        [Route("getemail")]
        public IActionResult Get(string token)
        {
            if (!authService.IsTokenValid(token))
                return StatusCode((int)HttpStatusCode.BadRequest);
            var claims = authService.GetTokenClaims(token);
            var emailId = claims.First().Value;
            return Ok(emailId);
        }

        private static IEnumerable<Claim> GetClaims(string email)
        {
            return new Claim[]
                {
                    new Claim(ClaimTypes.Email, email)
                };
        }
    }
}