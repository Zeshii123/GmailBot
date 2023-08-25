import os.path
import base64
import json
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Set the html file path, label file path and creds file path
#declare the scopes
html_template_path = 'template.html'
file_path = 'label.txt'
CREDENTIALS_FILE = 'credentials.json'
SCOPES = ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify']

def get_credentials():
    creds = None
    if os.path.exists('token.json'):
        try:
            creds = Credentials.from_authorized_user_file('token.json')
        except Exception as e:
            print(e)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
            # Make modifications to the credentials if needed
            # For example: credentials.refresh(request) to refresh the token

        # Create a dictionary representation of the credentials
        credentials_data = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }


        with open('token.json', 'w') as token:
            json.dump(credentials_data, token)
    return creds

def send_email(service, message, user_id='me'):
    try:
        message = (service.users().messages().send(userId=user_id, body=message).execute())
        print(f"Message sent. Message Id: {message['id']}")
        return message
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def create_message_with_html_template(from_email, to_email, subject, html_path, thread_id, message_id):
    with open(html_path, 'r') as html_file:
        html_content = html_file.read()

    message = {
        'raw': base64.urlsafe_b64encode(
            # f"From: {from_email}\n"
            f"To: {to_email}\n"
            f"Subject: Re: {subject}\n"
            f"References: {thread_id}, {message_id}\n"
            f"In-Reply-To: {message_id}\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            f"{html_content}".encode("utf-8")
        ).decode("utf-8"),
        'threadId': thread_id
    }
    return message


def list_labels(service, user_id='me'):
    try:
        labels = service.users().labels().list(userId=user_id).execute()
        return labels.get('labels', [])
    except Exception as e:
        print(f"An error occurred while listing labels: {e}")
        return []


def create_new_label(service, new_label_name, user_id='me'):
    label = {'name': new_label_name}
    new_label = service.users().labels().create(userId=user_id, body=label).execute()
    return new_label['id']

def apply_new_label(service, message_id, new_label_id, user_id='me'):
    body = {'addLabelIds': [new_label_id]}
    service.users().messages().modify(userId=user_id, id=message_id, body=body).execute()


def remove_old_label(service, label_id, message_id, user_id='me'):
    body = {'removeLabelIds': [label_id]}
    service.users().messages().modify(userId=user_id, id=message_id, body=body).execute()

def remove_label(service, label_id, user_id='me'):
    try:
        service.users().labels().delete(userId=user_id, id=label_id).execute()
        print("Labels removed successfully.")
    except Exception as e:
        print(f"An error occurred while removing labels: {e}")


def list_emails_with_label(service, label_id, user_id='me'):
    try:
        from itertools import groupby
        results = service.users().messages().list(userId=user_id, labelIds=[label_id]).execute()
        results = results.get('messages', [])
        grouped_data = {key: list(group) for key, group in groupby(results, key=lambda x: x['threadId'])}
        return grouped_data
    except Exception as e:
        print(f"An error occurred while listing emails with label: {e}")
        return []

def read_text_file(file_path):
    try:
        with open(file_path, 'r') as file:
            text = file.read()
            return text
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return None

def main():
    creds = get_credentials()
    service = build('gmail', 'v1', credentials=creds)

    # Fetch labels
    labels = list_labels(service)
    custom_label = read_text_file(file_path)
    desired_label = next((label for label in labels if label['name'].lower() == custom_label.lower()), None)
    if desired_label:
        current_label_id = desired_label['id']
        emails = list_emails_with_label(service, current_label_id)
        if not emails:
            print(f'No emails found under label {desired_label}.')
        else:
            print(f'Messages under label {desired_label}:')
            # Create a new label
            new_label_name = f"{desired_label['name']} - Responded"
            new_label = create_new_label(service, new_label_name)
            for email in emails.keys():
                print(email)
                msg = service.users().messages().get(userId='me', id=email).execute()
                msg_data = msg['payload']['headers']
                thread_id = msg['threadId']
                subject = next(item['value'] for item in msg_data if item['name'] == 'Subject')
                message_id = next(item['value'] for item in msg_data if item['name'].lower() == 'Message-ID'.lower())
                from_email = next(item['value'] for item in msg_data if item['name'] == 'To')
                to_email = next(item['value'] for item in msg_data if item['name'] == 'From').\
                    replace("<", "").replace(">", "").split(' ')[-1]
                print(f'Email ID: {message_id}')
                reply_message = create_message_with_html_template(from_email, to_email, subject, html_template_path,
                                                                  thread_id, message_id)

                # Send email in reply
                send_email(service, reply_message)

                # Apply the new label to messages
                apply_new_label(service, email, new_label)

                # Remove the old label from messages
                remove_old_label(service, current_label_id, email)

        # Remove the old label
        remove_label(service, label_id=current_label_id)
    else:
        print(f'No Label found against {custom_label}.')


if __name__ == '__main__':
    main()
