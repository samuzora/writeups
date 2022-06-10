from flask import Flask, render_template, redirect

app = Flask(__name__)

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/auth')
def auth():
    return redirect('http://challs.nusgreyhats.org:12326/auth')

@app.route('/flagis')
def flagis():
    return 'ok'    


app.run(host="0.0.0.0", port=80)
