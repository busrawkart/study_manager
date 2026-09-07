import requests

session = requests.Session()

login_url = "http://127.0.0.1:5000/login"

login_data = {
	"email": "busrawkartt@gmail.com",
	"password": "new67study67"
}

response = session.post(login_url, data=login_data)

print("Login status:", response.status_code)
print("Login response:", response.text)
print("Cookies:", session.cookies.get_dict())

api_url = "http://127.0.0.1:5000/api/tasks"

response = session.get(api_url)

print("API status:", response.status_code)
print("API response:", response.text)

