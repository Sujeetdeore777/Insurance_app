from flask_mail import Mail, Message
from flask import Flask



app =Flask(__name__)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'vb750718@gmail.com'
app.config['MAIL_PASSWORD'] = 'vsb750718'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)


@app.route("/")
def index():
   msg = Message('Hello', sender = 'vb750718@gmail.com', recipients = ['vb60419@gmail.com'])
   msg.body = "PATREC Contract created"
   mail.send(msg)
   return "Sent"

if __name__ == '__main__':
   app.run(debug = True)