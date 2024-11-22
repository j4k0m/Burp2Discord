from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (JMenuItem, JOptionPane, JPanel, JTextField, JLabel, 
                        BoxLayout, JButton, BorderFactory, SwingConstants)
from java.awt import Dimension, FlowLayout, Font, Color
from javax.swing import Box
from java.awt.event import ActionListener
from java.util import ArrayList
import json
import urllib2
from datetime import datetime
import os
import random

class SaveButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        self.extender.saveConfig()

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp2Discord")
        callbacks.registerContextMenuFactory(self)
        self.webhook_url = callbacks.loadExtensionSetting("discord_webhook_url") or ""
        self.setupUI()
        callbacks.addSuiteTab(self)
        
    def setupUI(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))
        
        titleLabel = JLabel("Discord Webhook Configuration", SwingConstants.LEFT)
        titleLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        titleLabel.setAlignmentX(JLabel.LEFT_ALIGNMENT)
        self.panel.add(titleLabel)
        self.panel.add(Box.createRigidArea(Dimension(0, 10)))
        
        configPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        configPanel.setMaximumSize(Dimension(800, 40))
        configPanel.setAlignmentX(JLabel.LEFT_ALIGNMENT)
        
        urlLabel = JLabel("Webhook URL: ")
        urlLabel.setFont(Font("Tahoma", Font.PLAIN, 12))
        self.urlField = JTextField(self.webhook_url, 45)
        self.urlField.setFont(Font("Tahoma", Font.PLAIN, 12))
        
        saveButton = JButton("Save")
        saveButton.setFont(Font("Tahoma", Font.BOLD, 12))
        saveButton.setBackground(Color(65, 105, 225))
        saveButton.setForeground(Color.WHITE)
        saveButton.addActionListener(SaveButtonListener(self))
        
        configPanel.add(urlLabel)
        configPanel.add(Box.createRigidArea(Dimension(5, 0)))
        configPanel.add(self.urlField)
        configPanel.add(Box.createRigidArea(Dimension(10, 0)))
        configPanel.add(saveButton)
        
        self.panel.add(configPanel)
        self.panel.add(Box.createRigidArea(Dimension(0, 20)))
        
        instructionsPanel = JPanel()
        instructionsPanel.setLayout(BoxLayout(instructionsPanel, BoxLayout.Y_AXIS))
        instructionsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "Instructions"
        ))
        instructionsPanel.setAlignmentX(JLabel.LEFT_ALIGNMENT)
        
        innerPanel = JPanel()
        innerPanel.setLayout(BoxLayout(innerPanel, BoxLayout.Y_AXIS))
        innerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        innerPanel.setAlignmentX(JLabel.LEFT_ALIGNMENT)
        
        instructions = [
            "1. Enter your Discord webhook URL above and click Save",
            "2. Right-click on any request in Burp Suite",
            "3. Select 'Send to Discord' from the context menu",
            "4. Add optional title and notes in the popup dialog",
            "5. The request and response will be sent to your Discord channel"
        ]
        
        for instruction in instructions:
            label = JLabel(instruction)
            label.setFont(Font("Tahoma", Font.PLAIN, 12))
            label.setAlignmentX(JLabel.LEFT_ALIGNMENT)
            innerPanel.add(label)
            innerPanel.add(Box.createRigidArea(Dimension(0, 5)))
        
        instructionsPanel.add(innerPanel)
        self.panel.add(instructionsPanel)
        self.panel.add(Box.createVerticalGlue())

    def saveConfig(self):
        new_url = self.urlField.getText()
        self.webhook_url = new_url
        self.callbacks.saveExtensionSetting("discord_webhook_url", new_url)
        JOptionPane.showMessageDialog(None, "Configuration saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE)

    def getTabCaption(self):
        return "Discord Webhook"
        
    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menuItems = ArrayList()
        sendItem = JMenuItem("Send to Discord")
        sendItem.addActionListener(lambda x, inv=invocation: self.send_to_discord(inv))
        menuItems.add(sendItem)
        return menuItems

    def get_notes_input(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        
        titleLabel = JLabel("Title:")
        titleField = JTextField(20)
        panel.add(titleLabel)
        panel.add(titleField)
        panel.add(Box.createRigidArea(Dimension(0, 10)))
        
        notesLabel = JLabel("Notes:")
        notesField = JTextField(20)
        panel.add(notesLabel)
        panel.add(notesField)
        
        result = JOptionPane.showConfirmDialog(None, panel, "Add Notes", JOptionPane.OK_CANCEL_OPTION)
        
        if result == JOptionPane.OK_OPTION:
            return {
                'title': titleField.getText() or "HTTP Request",
                'notes': notesField.getText() or ""
            }
        return None

    def send_to_discord(self, invocation):
        if not self.webhook_url:
            JOptionPane.showMessageDialog(None, "Discord webhook URL not configured", "Configuration Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            notes_data = self.get_notes_input()
            if not notes_data:
                return

            http_messages = invocation.getSelectedMessages()
            if not http_messages or len(http_messages) == 0:
                return

            request = http_messages[0]
            request_info = self.helpers.analyzeRequest(request)
            full_request = self.helpers.bytesToString(request.getRequest())
            response = request.getResponse()
            full_response = self.helpers.bytesToString(response) if response else "No response available"
            url = request_info.getUrl()
            method = request_info.getMethod()
            
            def clean_text(text):
                if text is None:
                    return ""
                if isinstance(text, bytes):
                    text = text.decode('utf-8', errors='replace')
                return ''.join(char if 32 <= ord(char) <= 126 or char in '\r\n\t' else '?' for char in text)

            request_filename = "request.txt"
            response_filename = "response.txt"
            
            with open(request_filename, 'wb') as f:
                request_data = self.helpers.bytesToString(request.getRequest())
                f.write(clean_text(request_data).encode('utf-8', errors='replace'))
            
            with open(response_filename, 'wb') as f:
                if request.getResponse():
                    response_data = self.helpers.bytesToString(request.getResponse())
                    f.write(clean_text(response_data).encode('utf-8', errors='replace'))
                else:
                    f.write("No response available".encode('utf-8'))

            embed = {
                "title": notes_data['title'][:256],
                "description": "**Notes:** {}\n\n**URL:** {} {}\n".format(
                    clean_text(notes_data['notes'])[:1024] or "No notes provided",
                    method,
                    str(url)
                ),
                "color": 7506394,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "footer": {"text": "Burp Suite Export"}
            }

            boundary = '----WebKitFormBoundary' + ''.join(['%x' % random.randrange(16) for _ in range(32)])
            body = []

            body.append('--' + boundary)
            body.append('Content-Disposition: form-data; name="payload_json"')
            body.append('Content-Type: application/json')
            body.append('')
            body.append(json.dumps({"embeds": [embed]}))

            body.append('--' + boundary)
            body.append('Content-Disposition: form-data; name="file1"; filename="{}"'.format(request_filename))
            body.append('Content-Type: text/plain')
            body.append('')
            with open(request_filename, 'rb') as f:
                body.append(f.read().decode('utf-8', errors='replace'))

            body.append('--' + boundary)
            body.append('Content-Disposition: form-data; name="file2"; filename="{}"'.format(response_filename))
            body.append('Content-Type: text/plain')
            body.append('')
            with open(response_filename, 'rb') as f:
                body.append(f.read().decode('utf-8', errors='replace'))

            body.append('--' + boundary + '--')
            body.append('')
            body = '\r\n'.join(body).encode('utf-8', errors='replace')

            discord_request = urllib2.Request(
                self.webhook_url,
                data=body,
                headers={
                    'Content-Type': 'multipart/form-data; boundary=' + boundary,
                    'User-Agent': 'Python/BurpChatHistoryBot'
                }
            )

            try:
                response = urllib2.urlopen(discord_request)
                if response.getcode() in [200, 204]:
                    JOptionPane.showMessageDialog(None, "Successfully sent to Discord", "Success", JOptionPane.INFORMATION_MESSAGE)
                else:
                    JOptionPane.showMessageDialog(None, "Unexpected response status: {}".format(response.getcode()), "Error", JOptionPane.ERROR_MESSAGE)
                response.close()

                os.remove(request_filename)
                os.remove(response_filename)

            except urllib2.HTTPError as e:
                error_body = e.read()
                JOptionPane.showMessageDialog(None, "HTTP Error: {} - {}\nResponse: {}".format(e.code, e.reason, error_body), "Error", JOptionPane.ERROR_MESSAGE)
                if os.path.exists(request_filename):
                    os.remove(request_filename)
                if os.path.exists(response_filename):
                    os.remove(response_filename)

            except urllib2.URLError as e:
                JOptionPane.showMessageDialog(None, "URL Error: {}".format(str(e.reason)), "Error", JOptionPane.ERROR_MESSAGE)
                if os.path.exists(request_filename):
                    os.remove(request_filename)
                if os.path.exists(response_filename):
                    os.remove(response_filename)

        except Exception as e:
            JOptionPane.showMessageDialog(None, "Error sending to Discord: {}".format(str(e)), "Error", JOptionPane.ERROR_MESSAGE)
            if os.path.exists(request_filename):
                os.remove(request_filename)
            if os.path.exists(response_filename):
                os.remove(response_filename)
