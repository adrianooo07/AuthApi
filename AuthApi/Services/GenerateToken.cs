using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthApi.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services
{
    public class GenerateToken
    {
        private readonly IConfiguration _configuration;

        public GenerateToken(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string Token(Guid id, string email, ICollection<Role> role)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("Token:secret").Value);

            var claimList = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, email)
            };

            foreach (var r in role)
            {
                claimList.Add(new Claim(ClaimTypes.Role, r.Name));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = _configuration.GetSection("Token:client").Value,
                Issuer = _configuration.GetSection("Token:audience").Value,
                Subject = new ClaimsIdentity(claimList),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
