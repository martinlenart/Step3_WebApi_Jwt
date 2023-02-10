using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Diagnostics.Metrics;

using Step3_WebApi_Jwt.Models;
using Step3_WebApi_Jwt.Services;
using Microsoft.AspNetCore.Authorization;

namespace Step3_WebApi_Jwt.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class QuotesController : ControllerBase
    {
        private ILoginService _loginService;
        private IMockupData _repo;
        private ILogger<QuotesController> _logger;


        //GET: api/Quotes
        //GET: api/Quotes/?count={count}
        //Below are good practice decorators to use for a GET request
        [Authorize(AuthenticationSchemes = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme, Policy = null, Roles = "Manager")]
        [HttpGet]
        [ProducesResponseType(200, Type = typeof(IEnumerable<GoodQuote>))]
        [ProducesResponseType(400, Type = typeof(string))]
         public IActionResult GetQoutes(string count)
        {
            _logger.LogInformation("GetQuotes initiated");

            if (string.IsNullOrWhiteSpace(count))
            {
                _logger.LogInformation("GetQuotes returned {count} items", _repo.Quotes.Count);
                return Ok(_repo.Quotes);
            }

            if (!int.TryParse(count, out int _count))
            {
                return BadRequest("count format error");
            }

            _count = Math.Min(_count, _repo.Quotes.Count);
            _logger.LogInformation("GetQuotes returned {_count} items", _count);
            return Ok(_repo.Quotes.Take(_count));
        }

        public QuotesController(IMockupData repo, ILogger<QuotesController> logger, ILoginService loginService)
        {
            _repo = repo;
            _logger = logger;
            _loginService = loginService;

            _logger.LogInformation($"QuotesController started.");
        }
    }
}