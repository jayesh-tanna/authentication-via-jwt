using CoreWebAPI.JWTAuthentication.Models;
using System.Collections.Generic;

namespace CoreWebAPI.JWTAuthentication.Services
{
    public interface IUserService
    {
        IEnumerable<User> List();
    }
}