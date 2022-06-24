using TokenTaskJwt.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace TokenTaskJwt.Repository
{
    public interface IUserRepository
    {
        UserModel GetUser(UserLog userMode);
    }

    public interface ITokenService
    {
        string BuildToken(string key, string issuer, UserModel user);
        bool ValidateToken(string key, string issuer, string audience, string token);
        bool IsTokenValid(string v1, string v2, string token);
    }


    public class UserRepository : IUserRepository
    {
        private readonly List<UserModel> users = new List<UserModel>();

        public UserRepository()
        {
            users.Add(new UserModel
            {
                UserName = "AbhishekPandey",
                Password = "Abhish123",
                Role = "Admin"
            });
            users.Add(new UserModel
            {
                UserName = "ShubhamChoudhary",
                Password = "Shubh321",
                Role = "Reviewer"
            });
            users.Add(new UserModel
            {
                UserName = "VipulSatle",
                Password = "Vip123",
                Role = "Reviewer"
            });
            users.Add(new UserModel
            {
                UserName = "SagarPratap",
                Password = "Sp123",
                Role = "User"
            });
            users.Add(new UserModel
            {
                UserName = "MonikaYadav",
                Password = "Monika321",
                Role = "User"
            });
        }
        public UserModel GetUser(UserLog userModel)
        {
            return users.Where(x => x.UserName.ToLower() == userModel.UserName.ToLower()
                && x.Password == userModel.Password).FirstOrDefault();
        }
    }

    public class TokenService : ITokenService
    {
        private const double EXPIRY_DURATION_MINUTES = 30;

        public string BuildToken(string key, string issuer, UserModel user)
        {
            var claims = new[] {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(ClaimTypes.NameIdentifier,
            Guid.NewGuid().ToString())
        };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var tokenDescriptor = new JwtSecurityToken(issuer, issuer, claims,
                expires: DateTime.Now.AddMinutes(EXPIRY_DURATION_MINUTES), signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
        public bool IsTokenValid(string key, string issuer, string token)
        {
            var mySecret = Encoding.UTF8.GetBytes(key);
            var mySecurityKey = new SymmetricSecurityKey(mySecret);
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(token,
                new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = issuer,
                    ValidAudience = issuer,
                    IssuerSigningKey = mySecurityKey,
                }, out SecurityToken validatedToken);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public bool ValidateToken(string key, string issuer, string audience, string token)
        {
            throw new NotImplementedException();
        }
    }



}
