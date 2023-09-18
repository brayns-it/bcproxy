namespace BCProxy
{
    public class ErrorResponse
    {
        public class ErrorMessage
        {
            public string message = "";
        }

        public ErrorMessage error = new();

        public ErrorResponse(Exception ex)
        {
            error.message = ex.Message;
        }
    }

    public class Endpoints
    {
        public class Endpoint
        {
            public string proxyUrl = "";
            public string internalUrl = "";
            public string login = "";
            public string password = "";

            public List<Token> tokens = new();
        }

        public class Token
        {
            public string id = "";
        }

        public List<Endpoint> endpoints = new();
    }
}
