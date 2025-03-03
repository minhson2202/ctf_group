import requests
import sys
import random
import string
import json
import os
from enum import Enum
from faker import Faker
from fake_useragent import UserAgent
from sys import argv, stderr

HOST = "http://192.168.33.161:1133"
EMAIL_DOMAIN = "memeil.pogg"
CREDENTIALS_FILE = "credentials.json"

faker = Faker()
ua = UserAgent()

class ExitStatus(Enum):
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECKER_ERROR = 110

def die(code: ExitStatus, msg: str):
    if msg:
        print(msg, file=sys.stderr)
    sys.exit(code.value)

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def save_credentials(email, password):
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as f:
            credentials = json.load(f)
    else:
        credentials = {}

    credentials[email] = password

    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(credentials, f)

def get_password(email):
    if not os.path.exists(CREDENTIALS_FILE):
        return None

    with open(CREDENTIALS_FILE, 'r') as f:
        credentials = json.load(f)

    return credentials.get(email)

class MemeilService:
    def __init__(self, host):
        self.session = requests.Session()
        self.session.host = host
        self.session.headers = {
            "Content-Type": "application/json",
            "User-Agent": ua.random 
        }

    def register(self, registration_data):
        try:
            registration_data.pop("", None)  # remove "" key if it exists
            r = self.session.post(f"{self.session.host}/auth/signup", json=registration_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to register in service: {e}")

        if r.status_code != 200:
            print(f"error: {r.status_code}")
            try:
                error_content = r.json()
                print(f"error details: {json.dumps(error_content, indent=4)}")
            except:
                print(f"error details: {r.text}")
            die(ExitStatus.MUMBLE, f"Unexpected /auth/signup code: {r.status_code}")

        if r.text.strip() == "":
            die(ExitStatus.MUMBLE, "Empty response after registration")

        try:
            response_json = r.json()
        except ValueError:
            print(f"non-JSON response: {r.text}")
            die(ExitStatus.MUMBLE, "Non-JSON response after registration")

        if "message" in response_json:
            print(f"registration message: {response_json['message']}")
            return "registration successful"
        else:
            print("registration successful with unknown response format.")
            return "registration successful"


    def login(self, login_data):
        try:
            r = self.session.post(f"{self.session.host}/auth/signin", json=login_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to sign in: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /auth/signin code: {r.status_code}")

        try:
            if r.text.strip() == "":
                die(ExitStatus.MUMBLE, "Empty response after login")
            response_json = r.json()
            token = response_json.get("token", "")
            if not token:
                die(ExitStatus.MUMBLE, "no token received after login")
            self.session.headers.update({"Authorization": f"Bearer {token}"})
            return token
        except Exception as e:
            die(ExitStatus.DOWN, f"failed to parse token after sign in: {e}")


    def send_mail(self, mail_data):
        try:
            r = self.session.post(f"{self.session.host}/api/send", json=mail_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"failed to send mail: {e}")

        if r.status_code != 200:
            try:
                response_json = r.json()
                error_message = response_json.get("message", r.text)
                die(ExitStatus.MUMBLE, f"Unexpected /api/send response code: {r.status_code}, message: {error_message}")
            except Exception as e:
                die(ExitStatus.DOWN, f"failed to parse error response: {e}")

        try:
            if r.text.strip() == "":
                die(ExitStatus.MUMBLE, "Empty response after sending mail")
            response_json = r.json()
            if "timestamp" in response_json:
                return response_json.get("timestamp")
            if response_json.get("status") != "OK":
                die(ExitStatus.MUMBLE, f"failed to send mail, response: {response_json}")
        except Exception as e:
            die(ExitStatus.DOWN, f"failed to parse response after sending mail: {e}")

            
    def get_all_mails(self):
        try:
            r = self.session.get(f"{self.session.host}/api/inbox")
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to get all mails: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/inbox code: {r.status_code}")

        try:
            response_json = r.json()
            return response_json
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to parse response for get all mails: {e}")
    
    def get_all_sent_mails(self):
        try:
            r = self.session.get(f"{self.session.host}/api/sent")
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to get sent mails: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/sent code: {r.status_code}")

        try:
            response_json = r.json()
            return response_json
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to parse response for get all sent mails: {e}")

    def export_mail(self, export_data):
        try:
            r = self.session.post(f"{self.session.host}/api/export", json=export_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to export mail: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/export code: {r.status_code}")

        response_text = r.text.strip()
        if response_text == "":
            die(ExitStatus.CORRUPT, "Empty response for export mail.")
        return {"status format": response_text}

    def get_mail_by_id(self, mail_id):
        try:
            r = self.session.get(f"{self.session.host}/api/{mail_id}")
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to get mail by ID: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/{mail_id} code: {r.status_code}")

        try:
            response_json = r.json()
            return response_json
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to parse response for get mail by ID: {e}")

    def delete_mail(self, mail_id):
        try:
            r = self.session.delete(f"{self.session.host}/api/{mail_id}")
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to delete mail: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/{mail_id} delete response code: {r.status_code}")

        try:
            response_json = r.json()
            if "deleted" in response_json and response_json["deleted"] == mail_id:
                return "mail deleted successfully"
            else:
                die(ExitStatus.MUMBLE, f"Failed to delete mail, response: {response_json}")
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to parse response after deleting mail: {e}")

    def get_all_folders(self):
        try:
            r = self.session.get(f"{self.session.host}/api/folder/all")
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to get all folders: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/folder/all code: {r.status_code}")

        try:
            response_json = r.json()
            return response_json
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to parse response for get all folders: {e}")

    def create_folder(self, folder_data):
        try:
            r = self.session.put(f"{self.session.host}/api/folder/create", json=folder_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to create folder: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/folder/create code: {r.status_code}")

        try:
            response_json = r.json()
        except ValueError:
            response_json = {"status": r.text.strip()}

        if isinstance(response_json, str):
            response_json = {"status": response_json}

        if response_json.get("status") != "OK" and "folder created" not in response_json.get("status", "").lower():
            die(ExitStatus.MUMBLE, f"Failed to create folder, response: {response_json}")

        return "folder created successfully"

    def get_folder_content(self, folder_name):
        try:
            r = self.session.get(f"{self.session.host}/api/folder/{folder_name}/")
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to get folder content: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/folder/{folder_name}/ code: {r.status_code}")

        try:
            response_json = r.json()
            return response_json
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to parse response for get folder content: {e}")

    def add_message_to_folder(self, folder_name, message_data):
        try:
            r = self.session.post(f"{self.session.host}/api/folder/{folder_name}/add", json=message_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to add message to folder: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/folder/{folder_name}/add code: {r.status_code}")

        try:
            response_json = r.json()
        except ValueError:
            response_json = {"status": r.text.strip()}

        if isinstance(response_json, str):
            response_json = {"status": response_json}

        if "added to the" not in response_json.get("status", "").lower():
            die(ExitStatus.MUMBLE, f"Failed to add message to folder, response: {response_json}")

        return "message added to folder successfully"

    def remove_message_from_folder(self, folder_name, message_data):
        try:
            r = self.session.put(f"{self.session.host}/api/folder/{folder_name}/remove", json=message_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to remove message from folder: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/folder/{folder_name}/remove code: {r.status_code}")

        try:
            response_json = r.json()
        except ValueError:
            response_json = {"status": r.text.strip()}

        if isinstance(response_json, str):
            response_json = {"status": response_json}

        if "removed from the" not in response_json.get("status", "").lower():
            die(ExitStatus.MUMBLE, f"Failed to remove message from folder, response: {response_json}")

        return "message removed from folder successfully"

    def replace_message_in_folder(self, folder_name, message_data):
        try:
            r = self.session.put(f"{self.session.host}/api/folder/{folder_name}/replace", json=message_data)
        except Exception as e:
            die(ExitStatus.DOWN, f"Failed to replace message in folder: {e}")

        if r.status_code != 200:
            die(ExitStatus.MUMBLE, f"Unexpected /api/folder/{folder_name}/replace code: {r.status_code}")

        try:
            response_json = r.json()
        except ValueError:
            response_json = {"status": r.text.strip()}

        if isinstance(response_json, str):
            response_json = {"status": response_json}

        if "replaced from the" not in response_json.get("status", "").lower():
            die(ExitStatus.MUMBLE, f"Failed to replace message in folder, response: {response_json}")

        return "message replaced in folder successfully"

formats = [
    "from: {{ .From }},\nto: {{ .Repo.GetName .To }} <{{ .To }}>,\ntitle: {{ .Title }},\ncontent: {{ .Body }}",
    "Sender: {{ .From }},\nRecipient: {{ .Repo.GetName .To }} <{{ .To }}>,\nSubject: {{ .Title }},\nMessage: {{ .Body }}",
    "Email from {{ .From }} to {{ .To }} titled {{ .Title }}: {{ .Body }}",
    "{{ .From }} -> {{ .To }}: {{ .Title }}\n{{ .Body }}",
    "{{ .Title }} by {{ .From }} to {{ .To }}: {{ .Body }}"
]

def get_random_format():
    return random.choice(formats)


def info(*other):
	print('{"vulns": 1, "timeout": 30, "attack_data": ""}', flush=True, end="")
	die(ExitStatus.OK)

def check(hostname):
    try:
        memeil_service = MemeilService(f"http://{hostname}:1133")
        username = faker.user_name()
        password = generate_password()
        registration_data = {
            "email": f"{username}@{EMAIL_DOMAIN}",
            "name": username,
            "password": password
        }

        print("registering user")
        memeil_service.register(registration_data)

        login_data = {
            "email": f"{username}@{EMAIL_DOMAIN}",
            "password": password
        }

        print("logging in user")
        login_token = memeil_service.login(login_data)
        print(f"login successful. Token: {login_token}")

        mail_data = {
            "body": faker.text(),  
            "from": f"{username}@{EMAIL_DOMAIN}",
            "title": faker.sentence(),  
            "to": f"{username}@{EMAIL_DOMAIN}"
        }
        print("sending mail")
        mail_id = memeil_service.send_mail(mail_data)
        print(f"sent mail successfully with ID: {mail_id}")

        print("receiving mails")
        all_mails = memeil_service.get_all_mails()
        if not all_mails:
            die(ExitStatus.CORRUPT, "No mails found after sending.")
        print("all mails:", all_mails)

        print("getting all sent mails")
        sent_mails = memeil_service.get_all_sent_mails()
        if not sent_mails:
            die(ExitStatus.CORRUPT, "No sent mails found.")
        print("sent mails:", sent_mails)

        print(f"fetching mail with ID: {mail_id}")
        mail_content = memeil_service.get_mail_by_id(mail_id)
        if not mail_content:
            die(ExitStatus.CORRUPT, "Mail content not found for sent mail.")
        print("fetched mail content:", mail_content)

        # print(f"deleting mail with ID: {mail_id}")
        # try:
        #     delete_status = memeil_service.delete_mail(mail_id)
        #     print(f"delete status: {delete_status}")
        # except Exception as e:
        #     print(f"Error during deletion: {e}")

        export_data = {
            "format": get_random_format(),
            "msgid": mail_id
        }
        print("exporting mail")
        export_status = memeil_service.export_mail(export_data)
        if not export_status:
            die(ExitStatus.CORRUPT, "Mail export failed.")
        print("export status:", export_status)

        print("retrieving all folders")
        all_folders = memeil_service.get_all_folders()
        if not all_folders:
            die(ExitStatus.CORRUPT, "No folders found.")
        print("all folders:", all_folders)

        print("creating folder")
        folder_data = {
            "foldername": faker.word()
        }
        print("foldername:", folder_data)
        create_status = memeil_service.create_folder(folder_data)
        if create_status != "folder created successfully":
            die(ExitStatus.CORRUPT, "Folder not created successfully.")
        print(create_status)

        print("getting folder content")
        folder_content = memeil_service.get_folder_content(folder_data["foldername"])
        print("folder content:", folder_content)

        print("adding message to folder")
        message_data = {
            "folder": folder_data["foldername"],
            "msgid": mail_id
        }
        add_status = memeil_service.add_message_to_folder(folder_data["foldername"], message_data)
        if add_status != "message added to folder successfully":
            die(ExitStatus.CORRUPT, "Message not added to folder successfully.")
        print(add_status)

        # print("removing message from folder")
        # remove_status = memeil_service.remove_message_from_folder(folder_data["foldername"], message_data)
        # if remove_status != "message removed from folder successfully":
        #     die(ExitStatus.CORRUPT, "Message not removed from folder successfully.")
        # print(remove_status)

        print("creating new folder for replacement")
        new_folder_data = {
            "foldername": faker.word()  
        }
        new_create_status = memeil_service.create_folder(new_folder_data)
        if new_create_status != "folder created successfully":
            die(ExitStatus.CORRUPT, "New folder not created successfully.")
        print(new_create_status)

        print("replacing message in folder")
        replace_data = {
            "foldername": new_folder_data["foldername"],
            "msgid": mail_id
        }
        replace_status = memeil_service.replace_message_in_folder(folder_data["foldername"], replace_data)
        if replace_status != "message replaced in folder successfully":
            die(ExitStatus.CORRUPT, "Message not replaced in folder successfully.")
        print(replace_status)

        print("retrieving all folders after operations")
        all_folders_after = memeil_service.get_all_folders()
        print("all folders after operations:", all_folders_after)
        die(ExitStatus.OK, "Check ALL OK")
    except Exception as e:
        die(ExitStatus.DOWN, f"Service check failed: {e}")

def put(hostname, flag_id, flag, vuln):
    try:
        memeil_service = MemeilService(f"http://{hostname}:1133")
        username = faker.user_name()
        password = generate_password()
        
        if vuln == "1":
            registration_data = {
                "email": f"{username}@{EMAIL_DOMAIN}",  
                "name": flag,
                "password": password
            }
            memeil_service.register(registration_data)
            save_credentials(f"{username}@{EMAIL_DOMAIN}", password)  # Save the credentials
            login_data = {
                "email": f"{username}@{EMAIL_DOMAIN}",
                "password": password
            }
            memeil_service.login(login_data)
        
        else:
            registration_data = {
                "email": f"{username}@{EMAIL_DOMAIN}",
                "name": username,
                "password": password
            }
            memeil_service.register(registration_data)
            save_credentials(f"{username}@{EMAIL_DOMAIN}", password)

            login_data = {
                "email": f"{username}@{EMAIL_DOMAIN}",
                "password": password
            }
            memeil_service.login(login_data)
        
            if vuln == "2":
                mail_data = {
                    "body": flag,
                    "from": f"{username}@{EMAIL_DOMAIN}",
                    "title": faker.sentence(),
                    "to": f"{username}@{EMAIL_DOMAIN}"
                }
                memeil_service.send_mail(mail_data)
            
            elif vuln == "3":
                folder_data = {
                    "foldername": flag
                }
                memeil_service.create_folder(folder_data)

            else:
                die(ExitStatus.CHECKER_ERROR, "vuln number is not accepted")

        email = f"{username}@{EMAIL_DOMAIN}"
        jd = json.dumps({
            "email": email,
            "vuln" : vuln
        })
        print(jd, flush=True)
        die(ExitStatus.OK, f"{jd}")
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to put flag: {e}")


def get(hostname, flag_id, flag):
    print("GET STARTED")
    try:
        data = json.loads(flag_id)
        if not data:
            raise ValueError
    except:
        die(
            ExitStatus.CHECKER_ERROR,
            f"Unexpected flagID from jury: {flag_id}! Are u using non-RuCTF checksystem?",
        )

    memeil_service = MemeilService(f"http://{hostname}:1133")
    try:
        email = data["email"]
        password = get_password(email) 
            
        if not password:
            die(ExitStatus.CORRUPT, "Password not found for the username")

        login_data = {
            "email": email,
            "password": password
        }
        memeil_service.login(login_data)
    except Exception as e:
            die(ExitStatus.CORRUPT, f"Error: {e}")
    
    if data["vuln"] == "1":
        resp = memeil_service.get_folder_content("not_a_name")
        for msg in resp.values():
            if flag in msg:
                die(ExitStatus.OK, "Flag found in usernames")
            die(ExitStatus.CORRUPT, "Flag not found")
        
    elif data["vuln"] =="2":
        all_mails = memeil_service.get_all_mails()
        for mail in all_mails.values():
            if flag in mail:
                die(ExitStatus.OK, "Flag found in emails")
        die(ExitStatus.CORRUPT, "Flag not found in emails")
        
    elif data["vuln"] == "3":
        all_folders = memeil_service.get_all_folders()
        for folder in all_folders:
            if flag in folder:
                die(ExitStatus.OK, "Flag found in folder names")
        die(ExitStatus.CORRUPT, "Flag not found in folder names")

    die(ExitStatus.CORRUPT, "Flag not found")



def main():
    try:
        mode = argv[1]
        hostname = argv[2]
        if mode == "info":
            info()
        elif mode == "check":
            check(hostname)
        elif mode == "put":
            flag_id = sys.argv[3]
            flag = sys.argv[4]
            vuln = sys.argv[5]
            put(hostname, flag_id, flag, vuln)
        elif mode == "get":
            flag_id = sys.argv[3]
            flag = sys.argv[4]
            get(hostname, flag_id, flag)
        else:
            raise IndexError
    except IndexError:
        die(
            ExitStatus.CHECKER_ERROR, f"Usage: {argv[0]} check|put|get IP FLAGID FLAG",
        )
if __name__ == "__main__":
    main()