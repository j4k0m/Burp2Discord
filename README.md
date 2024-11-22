# Burp2Discord

A Burp Suite extension that allows you to send HTTP requests and responses directly to Discord via webhooks.

## Features
- Send HTTP requests and responses to Discord with a single right-click
- Add custom titles and notes to each request
- Clean UI for webhook configuration
- Automatic file handling for large requests/responses
- Persistent webhook URL storage
- Error handling and user feedback

## Usage
1. Configure your Discord webhook URL in the "Discord Webhook" tab
2. Right-click on any request in Burp Suite
3. Select "Send to Discord" from the context menu
4. Add an optional title and notes
5. The request and response will be sent to your Discord channel as:
   - An embed with title, notes, and URL
   - Two text files containing the full request and response

## Author
Burp2Discord by Aymen @J4k0m | LinkedIn: linkedin.com/in/jakom/
