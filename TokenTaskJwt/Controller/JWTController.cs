using Microsoft.AspNetCore.Mvc;
using TokenTaskJwt.Models;
using Microsoft.AspNetCore.Authorization;
using TokenTaskJwt.Repository;
using ITokenService = TokenTaskJwt.Repository.ITokenService;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System;

namespace TokenTaskJwt.Controllers
{
    public class JWTController : Controller
    {
        private readonly IConfiguration _config;
        private readonly IUserRepository _userRepository;
        private readonly ITokenService _tokenService;
        private string generatedToken = null;

        public JWTController(IConfiguration config, ITokenService tokenService, IUserRepository userRepository)
        {
            _config = config;
            _tokenService = tokenService;
            _userRepository = userRepository;
        }

        public IActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        [Route("login")]
        [HttpPost]
        public IActionResult Login(UserLog userModel)
        {
            if (string.IsNullOrEmpty(userModel.UserName) || string.IsNullOrEmpty(userModel.Password))
            {
                return (RedirectToAction("Error"));
            }
            IActionResult response = Unauthorized();
            var validUser = GetUser(userModel);

            if (validUser != null)
            {
                generatedToken = _tokenService.BuildToken(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), validUser);
                if (generatedToken != null)
                {
                    HttpContext.Session.SetString("Token", generatedToken);
                    return RedirectToAction("MainWindow");
                }
                else
                {
                    return (RedirectToAction("Error"));
                }
            }
            else
            {
                return (RedirectToAction("Error"));
            }
        }

        private UserModel GetUser(UserLog userModel)
        {
            // Write your code here to authenticate the user     
            return _userRepository.GetUser(userModel);
        }

        [Authorize]
        [Route("mainwindow")]
        [HttpGet]
        public IActionResult MainWindow()
        {
            string token = HttpContext.Session.GetString("Token");
            if (token == null)
            {
                return (RedirectToAction("Index"));
            }
            if (!_tokenService.IsTokenValid(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token))
            {
                return (RedirectToAction("Index"));
            }
            ViewBag.Message = BuildMessage(token, 50);
            return View();
        }

        public IActionResult Error()
        {
            ViewBag.Message = "An error occured...";
            return View();
        }

        private string BuildMessage(string stringToSplit, int chunkSize)
        {
            var data = Enumerable.Range(0, stringToSplit.Length / chunkSize).Select(i => stringToSplit.Substring(i * chunkSize, chunkSize));
            string result = "The generated token is:";
            foreach (string str in data)
            {
                result += Environment.NewLine + str;
            }
            return result;
        }
    }


}
