using CoreWebAPI.JWTAuthentication.Models;
using CoreWebAPI.JWTAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;

namespace CoreWebAPI.JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [Authorize]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;

        public UserController(IAuthService authService, IUserService userService)
        {
            _authService = authService;
            _userService = userService;
        }

        [Route("login")]
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Post([FromBody]User user)
        {
            var result = _userService.List().FirstOrDefault(u => u.LoginId == user.LoginId && u.Password == user.Password);

            if (result == null)
                return StatusCode((int)HttpStatusCode.Unauthorized);

            var token = _authService.GenerateToken(GetClaims(result.LoginId));

            return Ok(token);
        }

        [Route("list")]
        public IActionResult Get()
        {
            return Ok(_userService.List());
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