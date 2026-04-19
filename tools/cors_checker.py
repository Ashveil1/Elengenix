import requests

def check_cors(url):
    """
    Check for CORS misconfiguration vulnerabilities.
    """
    results = {}
    origin_to_test = "http://evil.com"
    headers = {"Origin": origin_to_test}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # Check for vulnerable headers
        access_control_allow_origin = response.headers.get("Access-Control-Allow-Origin")
        access_control_allow_credentials = response.headers.get("Access-Control-Allow-Credentials")

        if access_control_allow_origin == origin_to_test:
            results["vulnerable"] = True
            results["reason"] = "Access-Control-Allow-Origin reflects Origin header."
        elif access_control_allow_origin == "*":
            results["warning"] = "Wildcard (*) Access-Control-Allow-Origin."
        
        if access_control_allow_credentials == "true":
            results["credentials_allowed"] = True

        return results
    except Exception as e:
        return {"error": str(e)}
