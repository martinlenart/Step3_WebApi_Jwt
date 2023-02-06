using System;
using Step3_WebApi_Jwt.Models;


namespace Step3_WebApi_Jwt.Services
{
    public interface ILoginService
    {
        bool LoginUser(string UserName, string Password, out User user);
        bool ValidateApiKey(string apiKey, out User loggedInUser);

        List<User> LoggedinUsers { get; }
    }


    public class LoginService : ILoginService
	{
        private static readonly object _locker = new();

        private List<User> _users = AppConfig.GetUsers;
        private Dictionary<string, User> _apiKeysInUse = new Dictionary<string, User>();

		public LoginService()
		{
		}

        public bool LoginUser(string UserName, string Password, out User user)
        {
            lock (_locker)
            {
                var u = _users.Find(x => ((x.Name.Equals(UserName, StringComparison.OrdinalIgnoreCase) || x.Email.Equals(UserName, StringComparison.OrdinalIgnoreCase))
                    && x.Password.Equals(Password, StringComparison.OrdinalIgnoreCase)));
                if (u != null)
                {
                    user = u;
                    _apiKeysInUse.TryAdd(u.apiKey, user);
                    return true;
                }

                user = null;
                return false;
            }
        }

        public void LogoutUser(string apiKey)
        {
            lock (_locker)
            {
                _apiKeysInUse.Remove(apiKey);
            }
        }

        public bool ValidateApiKey(string apiKey, out User loggedInUser)
        {
            lock (_locker)
            {
                loggedInUser = null;
                if (string.IsNullOrWhiteSpace(apiKey))
                    return false;

                return _apiKeysInUse.TryGetValue(apiKey, out loggedInUser);
            }
        }

        public List<User> LoggedinUsers
        {
            get
            {
                lock (_locker) return _apiKeysInUse.Values.ToList();
            }
        }
    }
}

