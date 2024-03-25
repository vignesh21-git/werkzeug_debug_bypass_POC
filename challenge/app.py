from flask import Flask, render_template, request,url_for 
from functools import wraps
import sys
import uuid
import typing as t
import pwd
import os
import werkzeug.debug
from werkzeug.serving import run_simple
import multiprocessing


app = Flask(__name__,template_folder='templates', static_url_path='/static')

def sanitize_file_name(file_name):
    # Split the file_name by "../"
    parts = file_name.split("../")
    
    # Rebuild the file_name with the specified replacements
    # The first part is kept as is (since the first "../" is removed),
    # then join the remaining parts with "." (for subsequent "../" replacements)
    sanitized_file_name = parts[0] + ".".join(parts[1:])
    
    # If the original file_name started with "../", we remove the leading part
    if file_name.startswith("../"):
        sanitized_file_name = sanitized_file_name[1:]  # Remove the first character, which is now incorrect
    
    print(sanitized_file_name)
    return sanitized_file_name

@app.route('/readfile') 
def readfile():
    file_name = request.args.get('file')  # Retrieves the file name from the GET request
    if not file_name:
        return "File name not provided", 400
    
    sanitized_file = sanitize_file_name(file_name)

    # Naively creating the file path - this is vulnerable to path traversal attacks
    file_path = 'static/' + sanitized_file

    try:
        # Attempt to open and read the file
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return "File not found", 404


# Route for the home page
@app.route('/')
def index():
    return render_template('index.html')

# Route for the about page
@app.route('/blog')
def about():
    return render_template('blog.html')

# Route for the contactpage
@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

def initialize():
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        user = pwd.getpwuid(os.getuid())[0]
        modname = getattr(app, "__module__", t.cast(object, app).__class__.__module__)
        mod = sys.modules.get(modname)
        app_name = getattr(app, "__name__", type(app).__name__)
        mod_file_loc = getattr(mod, '__file__', None)
        mac_addr = str (uuid.getnode ())
        machine_id = werkzeug.debug.get_machine_id()

        print("User: %s\nModule: %s\nModule Name: %s\nApp Location: %s\nMac Address: %s\nWerkzeug Machine ID: %s\n"
            % (user, modname, app_name, mod_file_loc, mac_addr, machine_id))

def start_server():
    run_simple('0.0.0.0', 7777, app, use_reloader=True, use_debugger=True, use_evalex=True)


if __name__ == '__main__':
    proc = multiprocessing.Process(target=start_server)
    proc.start()
    initialize()

