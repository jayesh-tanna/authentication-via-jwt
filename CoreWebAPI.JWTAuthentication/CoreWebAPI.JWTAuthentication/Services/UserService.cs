using CoreWebAPI.JWTAuthentication.Models;
using System.Collections.Generic;

namespace CoreWebAPI.JWTAuthentication.Services
{
    public class UserService : IUserService
    {
        public IEnumerable<User> List()
        {
            return new List<User>()
            {
                new User() { LoginId = "abc", Password = "abc" },
                new User() { LoginId = "123", Password = "123" }
            };
        }
    }
}