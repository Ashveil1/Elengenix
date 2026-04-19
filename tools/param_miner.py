import requests

def mine_parameters(url, common_params=["id", "page", "debug", "admin", "v1", "v2"]):
    """
    Check for hidden parameters by fuzzing with common parameter names.
    If the response changes (e.g., status code or content length), 
    the parameter might exist.
    """
    try:
        baseline_response = requests.get(url, timeout=10)
        baseline_length = len(baseline_response.content)
        baseline_status = baseline_response.status_code

        found_params = []
        for param in common_params:
            test_url = f"{url}?{param}=test"
            response = requests.get(test_url, timeout=10)
            
            # If status or length changes, the parameter might be functional
            if response.status_code != baseline_status or abs(len(response.content) - baseline_length) > 100:
                found_params.append(param)
        
        return found_params
    except Exception as e:
        return {"error": str(e)}
