using CoreWebAPI.JWTAuthentication.Models;
using CoreWebAPI.JWTAuthentication.Services;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
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
            if (!user.LoginId.Equals("abc") || !user.Password.Equals("abc"))
            {
                return StatusCode((int)HttpStatusCode.Unauthorized);
            }

            var token = authService.GenerateToken(GetClaims(user.LoginId));

            return Ok(token);
        }

        [Route("getemail")]
        public IActionResult Get(string token)
        {
            if (authService.IsTokenValid(token))
                return StatusCode((int)HttpStatusCode.BadRequest);
            return Ok("Valid token");
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
