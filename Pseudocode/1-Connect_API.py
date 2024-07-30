import requests

class CloudflareAPI:
    def __init__(self, email, api_key):
        self.email = email
        self.api_key = api_key
        self.base_url = "https://api.cloudflare.com/client/v4"

    def get_zone_settings(self, zone_id):
        url = f"{self.base_url}/zones/{zone_id}/settings"
        headers = {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch settings for zone {zone_id}")

    def update_zone_setting(self, zone_id, setting_name, new_value):
        url = f"{self.base_url}/zones/{zone_id}/settings/{setting_name}"
        headers = {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        data = {"value": new_value}
        response = requests.patch(url, headers=headers, json=data)
        if response.status_code == 200:
            return True
        else:
            raise Exception(f"Failed to update setting {setting_name} for zone {zone_id}")
