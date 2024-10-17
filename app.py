from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from openpyxl import Workbook
from io import BytesIO
import os
import requests
import base64
from flask import send_from_directory

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usb_hub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'screenshots'  # Folder to save screenshots

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# CrowdStrike API Configuration
CROWDSTRIKE_CLIENT_ID = 'your_client_id'
CROWDSTRIKE_CLIENT_SECRET = 'your_client_secret'
CROWDSTRIKE_TOKEN_URL = "https://api.crowdstrike.com/oauth2/token"
CROWDSTRIKE_DETECTIONS_URL = "https://api.crowdstrike.com/detections/queries/detections/v1"
STATIC_HOSTNAME = "your-static-hostname"  # Replace with your actual static hostname

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    detections = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_crowdstrike_token():
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': CROWDSTRIKE_CLIENT_ID,
        'client_secret': CROWDSTRIKE_CLIENT_SECRET
    }
    response = requests.post(CROWDSTRIKE_TOKEN_URL, headers=headers, data=data)
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        raise Exception(f"Failed to get token: {response.status_code}, {response.text}")

def query_detections_by_hostname(token, hostname):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    params = {
        'filter': f'hostname:"{hostname}"'
    }
    response = requests.get(CROWDSTRIKE_DETECTIONS_URL, headers=headers, params=params)
    if response.status_code == 200:
        detection_ids = response.json().get('resources', [])
        return len(detection_ids) > 0
    else:
        raise Exception(f"Failed to query detections: {response.status_code}, {response.text}")

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        company = request.form['company']
        date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        
        existing_record = Record.query.filter_by(
            first_name=first_name,
            last_name=last_name,
            company=company
        ).first()
        
        if existing_record:
            flash(f'A record for {first_name} {last_name} from {company} already exists.', 'error')
            return redirect(url_for('index'))
        
        new_record = Record(first_name=first_name, last_name=last_name, company=company, date=date)
        db.session.add(new_record)
        db.session.commit()
        
        try:
            token = get_crowdstrike_token()
            has_detections = query_detections_by_hostname(token, STATIC_HOSTNAME)
            new_record.detections = has_detections
            db.session.commit()
        except Exception as e:
            flash(f'Error checking detections: {str(e)}', 'error')
        
        flash('Record added successfully!', 'success')
        return redirect(url_for('scan_instructions'))
    
    return render_template('index.html', current_date=datetime.now().strftime('%Y-%m-%d'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email or log in.')
            return redirect(url_for('register'))
        
        new_user = User(email=email, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/scan-instructions')
@login_required
def scan_instructions():
    return render_template('scan_instructions.html', hostname=STATIC_HOSTNAME, username=current_user.email)

@app.route('/save-screenshot', methods=['POST'])
@login_required
def save_screenshot():
    data = request.json
    image_data = data['image'].split(',')[1]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{current_user.email}.png"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    with open(filepath, "wb") as fh:
        fh.write(base64.decodebytes(image_data.encode()))
    
    return jsonify({'success': True, 'filename': filename})

@app.route('/check-detections', methods=['POST'])
@login_required
def check_detections():
    try:
        token = get_crowdstrike_token()
        has_detections = query_detections_by_hostname(token, STATIC_HOSTNAME)
        return jsonify({'has_detections': has_detections})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/search')
@login_required
def search():
    company = request.args.get('company', '')
    display_all = request.args.get('display_all', 'false')

    if display_all == 'true':
        results = Record.query.all()
    elif company:
        results = Record.query.filter(Record.company.ilike(f'%{company}%')).all()
    else:
        results = []

    return render_template('search.html', records=results)



# ... (previous code remains the same)

@app.route('/image_search')
@login_required
def image_search():
    return render_template('image_search.html')

@app.route('/search_images')
@login_required
def search_images():
    query = request.args.get('query', '').lower()
    images = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if query in filename.lower():
            images.append(filename)
    return jsonify(images)

@app.route('/screenshots/<path:filename>')
@login_required
def serve_screenshot(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ... (rest of the code remains the same)



@app.route('/export')
@login_required
def export_excel():
    records = Record.query.all()

    wb = Workbook()
    ws = wb.active
    ws.title = "USB Hub Records"

    headers = ['First Name', 'Last Name', 'Company', 'Date', 'Detections']
    ws.append(headers)

    for record in records:
        ws.append([record.first_name, record.last_name, record.company, record.date.strftime('%Y-%m-%d'), 'Yes' if record.detections else 'No'])

    excel_file = BytesIO()
    wb.save(excel_file)
    excel_file.seek(0)

    return send_file(excel_file, 
                     download_name='usb_hub_records.xlsx',
                     as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create tables that don't exist yet
    app.run(debug=True)

