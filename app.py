#!/usr/bin/env python3
"""
Roleplay Circles MVP
Invite-based circles for sales teams to find roleplay partners.
"""

import json
import os
import secrets
import string
from datetime import datetime, timedelta
from dateutil import parser as date_parser
from flask import Flask, render_template, jsonify, request, redirect, url_for
from icalendar import Calendar
import requests
import pytz

app = Flask(__name__)

# Paths - use /data for persistence on Render, fallback to local for dev
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def is_data_dir_ready():
    """Check if /data exists AND is writable."""
    if not os.path.exists('/data'):
        return False
    try:
        test_file = '/data/.write_test'
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return True
    except Exception:
        return False

DATA_DIR = '/data' if is_data_dir_ready() else BASE_DIR
CONFIG_PATH = os.path.join(DATA_DIR, 'config.json')
STATE_PATH = os.path.join(DATA_DIR, 'state.json')
NOTIFICATIONS_PATH = os.path.join(DATA_DIR, 'notifications.json')
CIRCLES_PATH = os.path.join(DATA_DIR, 'circles.json')


def generate_code(length=6):
    """Generate a random invite code."""
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def load_circles():
    if os.path.exists(CIRCLES_PATH):
        with open(CIRCLES_PATH, 'r') as f:
            return json.load(f)
    return {"circles": []}


def save_circles(data):
    with open(CIRCLES_PATH, 'w') as f:
        json.dump(data, f, indent=2)


def get_circle(code):
    data = load_circles()
    for circle in data['circles']:
        if circle['code'] == code:
            return circle
    return None


def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, 'r') as f:
            return json.load(f)
    return {"noshow_events": [], "available_users": {}}


def save_state(state):
    with open(STATE_PATH, 'w') as f:
        json.dump(state, f, indent=2)


def add_notification(notification):
    """Add a notification to the queue."""
    notifications = []
    if os.path.exists(NOTIFICATIONS_PATH):
        with open(NOTIFICATIONS_PATH, 'r') as f:
            notifications = json.load(f)
    
    notification['timestamp'] = datetime.now().isoformat()
    notification['delivered'] = False
    notifications.append(notification)
    
    with open(NOTIFICATIONS_PATH, 'w') as f:
        json.dump(notifications, f, indent=2)


def fetch_calendar_events(ics_url, timezone_str='America/Chicago'):
    """Fetch and parse events from an ICS URL."""
    if not ics_url:
        return []
    
    try:
        response = requests.get(ics_url, timeout=10)
        response.raise_for_status()
        cal = Calendar.from_ical(response.content)
    except Exception as e:
        print(f"Error fetching calendar: {e}")
        return []
    
    tz = pytz.timezone(timezone_str)
    today = datetime.now(tz).date()
    events = []
    
    for component in cal.walk():
        if component.name == "VEVENT":
            dtstart = component.get('dtstart')
            if dtstart:
                start = dtstart.dt
                if isinstance(start, datetime):
                    if start.tzinfo is None:
                        start = tz.localize(start)
                    else:
                        start = start.astimezone(tz)
                    
                    if start.date() == today:
                        dtend = component.get('dtend')
                        end = dtend.dt if dtend else start + timedelta(hours=1)
                        if isinstance(end, datetime):
                            if end.tzinfo is None:
                                end = tz.localize(end)
                            else:
                                end = end.astimezone(tz)
                        
                        summary = str(component.get('summary', 'No Title'))
                        uid = str(component.get('uid', ''))
                        
                        events.append({
                            'uid': uid,
                            'summary': summary,
                            'start': start.isoformat(),
                            'end': end.isoformat(),
                            'start_time': start.strftime('%I:%M %p'),
                            'end_time': end.strftime('%I:%M %p'),
                            'start_dt': start
                        })
    
    events.sort(key=lambda x: x['start_dt'])
    for e in events:
        del e['start_dt']
    
    return events


def is_in_availability_window(user):
    """Check if current time is within user's availability window."""
    tz = pytz.timezone(user.get('timezone', 'America/Chicago'))
    now = datetime.now(tz)
    current_hour = now.hour
    
    start = user.get('start_hour', 9)
    end = user.get('end_hour', 18)
    
    return start <= current_hour < end


def check_event_needs_noshow_prompt(event, delay_minutes=10):
    """Check if an event started more than X minutes ago."""
    tz = pytz.timezone('America/Chicago')
    now = datetime.now(tz)
    start = date_parser.parse(event['start'])
    
    if start.tzinfo is None:
        start = tz.localize(start)
    
    minutes_since_start = (now - start).total_seconds() / 60
    
    return 0 < minutes_since_start < 60 and minutes_since_start >= delay_minutes


# ============ ROUTES ============

@app.route('/')
def home():
    """Landing page - create a circle."""
    return render_template('home.html')


@app.route('/create', methods=['POST'])
def create_circle():
    """Create a new circle."""
    data = request.json
    name = data.get('name', '').strip()
    creator_name = data.get('creator_name', '').strip()
    zoom_link = data.get('zoom_link', '').strip()
    admin_code = data.get('admin_code', '').strip()
    
    # Check admin code if set
    required_code = os.environ.get('ADMIN_CODE', '')
    if required_code and admin_code != required_code:
        return jsonify({'error': 'Admin code required to create circles'}), 403
    
    if not name or not creator_name:
        return jsonify({'error': 'Circle name and your name are required'}), 400
    
    code = generate_code()
    
    # Create circle
    circles_data = load_circles()
    
    creator_id = creator_name.lower().replace(' ', '_')
    
    new_circle = {
        'code': code,
        'name': name,
        'created_at': datetime.now().isoformat(),
        'members': [
            {
                'id': creator_id,
                'name': creator_name,
                'zoom_link': zoom_link,
                'ics_url': '',
                'timezone': 'America/Chicago',
                'start_hour': 9,
                'end_hour': 18,
                'is_creator': True
            }
        ]
    }
    
    circles_data['circles'].append(new_circle)
    save_circles(circles_data)
    
    return jsonify({
        'success': True,
        'code': code,
        'circle': new_circle,
        'invite_link': f"/join/{code}"
    })


@app.route('/join/<code>')
def join_page(code):
    """Join page for a circle."""
    circle = get_circle(code)
    if not circle:
        return render_template('error.html', message="Circle not found. Check your invite link."), 404
    
    return render_template('join.html', circle=circle, code=code)


@app.route('/join/<code>/submit', methods=['POST'])
def join_circle(code):
    """Submit join request."""
    circle = get_circle(code)
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404
    
    data = request.json
    name = data.get('name', '').strip()
    zoom_link = data.get('zoom_link', '').strip()
    
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    
    # Check if name already exists
    member_id = name.lower().replace(' ', '_')
    for member in circle['members']:
        if member['id'] == member_id:
            return jsonify({'error': 'Someone with that name is already in the circle'}), 400
    
    # Add member
    circles_data = load_circles()
    for c in circles_data['circles']:
        if c['code'] == code:
            c['members'].append({
                'id': member_id,
                'name': name,
                'zoom_link': zoom_link,
                'ics_url': '',
                'timezone': 'America/Chicago',
                'start_hour': 9,
                'end_hour': 18,
                'is_creator': False
            })
            break
    
    save_circles(circles_data)
    
    return jsonify({
        'success': True,
        'redirect': f"/c/{code}?user={member_id}"
    })


@app.route('/c/<code>')
def circle_app(code):
    """Main circle app view."""
    circle = get_circle(code)
    if not circle:
        return render_template('error.html', message="Circle not found."), 404
    
    user_id = request.args.get('user')
    user = None
    
    if user_id:
        for member in circle['members']:
            if member['id'] == user_id:
                user = member
                break
    
    if not user and circle['members']:
        user = circle['members'][0]
    
    return render_template('circle.html', circle=circle, user=user, code=code)


@app.route('/api/circle/<code>/status')
def circle_status(code):
    """Get status for a circle."""
    circle = get_circle(code)
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404
    
    state = load_state()
    circle_available = state.get('available_users', {}).get(code, [])
    
    members = []
    available_members = []
    
    for member in circle['members']:
        is_available = member['id'] in circle_available
        member_status = {
            'id': member['id'],
            'name': member['name'],
            'available': is_available,
            'zoom_link': member.get('zoom_link', ''),
            'in_availability_window': is_in_availability_window(member)
        }
        members.append(member_status)
        if is_available:
            available_members.append(member_status)
    
    return jsonify({
        'circle': circle['name'],
        'members': members,
        'available_count': len(available_members),
        'available_members': available_members,
        'group_session_ready': len(available_members) >= 2
    })


@app.route('/api/circle/<code>/available', methods=['POST'])
def set_available(code):
    """Set a user as available."""
    circle = get_circle(code)
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404
    
    data = request.json
    user_id = data.get('user_id')
    
    # Verify user is in circle
    user = None
    for member in circle['members']:
        if member['id'] == user_id:
            user = member
            break
    
    if not user:
        return jsonify({'error': 'User not in circle'}), 404
    
    state = load_state()
    if 'available_users' not in state:
        state['available_users'] = {}
    if code not in state['available_users']:
        state['available_users'][code] = []
    
    if user_id not in state['available_users'][code]:
        state['available_users'][code].append(user_id)
        save_state(state)
        
        # Notify others
        available_count = len(state['available_users'][code])
        available_names = [m['name'] for m in circle['members'] if m['id'] in state['available_users'][code]]
        
        for member in circle['members']:
            if member['id'] != user_id:
                if available_count >= 2:
                    msg = f"🎯 {user['name']} is available!\n\n{available_count} people ready: {', '.join(available_names)}"
                else:
                    msg = f"🎯 {user['name']} is available for roleplay!"
                
                add_notification({
                    'type': 'available',
                    'circle_code': code,
                    'to_user_id': member['id'],
                    'from_name': user['name'],
                    'from_user_id': user_id,
                    'zoom_link': user.get('zoom_link', ''),
                    'available_count': available_count,
                    'message': msg
                })
    
    return jsonify({
        'success': True,
        'available_count': len(state['available_users'][code])
    })


@app.route('/api/circle/<code>/unavailable', methods=['POST'])
def set_unavailable(code):
    """Set a user as unavailable."""
    data = request.json
    user_id = data.get('user_id')
    
    state = load_state()
    
    if code in state.get('available_users', {}):
        if user_id in state['available_users'][code]:
            state['available_users'][code].remove(user_id)
            save_state(state)
    
    return jsonify({'success': True})


@app.route('/api/circle/<code>/events/<user_id>')
def get_events(code, user_id):
    """Get today's events for a user."""
    circle = get_circle(code)
    if not circle:
        return jsonify({'error': 'Circle not found', 'events': []})
    
    user = None
    for member in circle['members']:
        if member['id'] == user_id:
            user = member
            break
    
    if not user:
        return jsonify({'error': 'User not found', 'events': []})
    
    state = load_state()
    events = fetch_calendar_events(user.get('ics_url', ''), user.get('timezone', 'America/Chicago'))
    
    for event in events:
        event['needs_noshow_prompt'] = check_event_needs_noshow_prompt(event, 10)
        event['marked_noshow'] = event['uid'] in state.get('noshow_events', [])
    
    return jsonify({
        'events': events,
        'user': user['name']
    })


@app.route('/api/circle/<code>/noshow', methods=['POST'])
def mark_noshow(code):
    """Mark event as no-show."""
    circle = get_circle(code)
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404
    
    data = request.json
    user_id = data.get('user_id')
    event_uid = data.get('event_uid')
    
    user = None
    for member in circle['members']:
        if member['id'] == user_id:
            user = member
            break
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    state = load_state()
    
    if event_uid not in state.get('noshow_events', []):
        if 'noshow_events' not in state:
            state['noshow_events'] = []
        state['noshow_events'].append(event_uid)
    
    # Also mark available
    if 'available_users' not in state:
        state['available_users'] = {}
    if code not in state['available_users']:
        state['available_users'][code] = []
    if user_id not in state['available_users'][code]:
        state['available_users'][code].append(user_id)
    
    save_state(state)
    
    # Notify others
    available_count = len(state['available_users'][code])
    for member in circle['members']:
        if member['id'] != user_id:
            add_notification({
                'type': 'noshow',
                'circle_code': code,
                'to_user_id': member['id'],
                'from_name': user['name'],
                'zoom_link': user.get('zoom_link', ''),
                'message': f"🎯 {user['name']} had a no-show! Available for roleplay."
            })
    
    return jsonify({'success': True})


@app.route('/api/circle/<code>/settings', methods=['POST'])
def update_settings(code):
    """Update user settings."""
    data = request.json
    user_id = data.get('user_id')
    
    circles_data = load_circles()
    
    for circle in circles_data['circles']:
        if circle['code'] == code:
            for member in circle['members']:
                if member['id'] == user_id:
                    if 'zoom_link' in data:
                        member['zoom_link'] = data['zoom_link']
                    if 'ics_url' in data:
                        member['ics_url'] = data['ics_url']
                    if 'start_hour' in data:
                        member['start_hour'] = data['start_hour']
                    if 'end_hour' in data:
                        member['end_hour'] = data['end_hour']
                    break
            break
    
    save_circles(circles_data)
    return jsonify({'success': True})


@app.route('/api/circle/<code>/notifications')
def get_notifications(code):
    """Get notifications for a circle."""
    if os.path.exists(NOTIFICATIONS_PATH):
        with open(NOTIFICATIONS_PATH, 'r') as f:
            notifications = json.load(f)
        recent = [n for n in notifications 
                  if not n.get('delivered') 
                  and n.get('circle_code') == code
                  and datetime.fromisoformat(n['timestamp']) > datetime.now() - timedelta(hours=1)]
        return jsonify({'notifications': recent})
    return jsonify({'notifications': []})


@app.route('/api/circle/<code>/notifications/mark-delivered', methods=['POST'])
def mark_delivered(code):
    """Mark notification as delivered."""
    data = request.json
    timestamp = data.get('timestamp')
    
    if os.path.exists(NOTIFICATIONS_PATH):
        with open(NOTIFICATIONS_PATH, 'r') as f:
            notifications = json.load(f)
        
        for n in notifications:
            if n.get('timestamp') == timestamp:
                n['delivered'] = True
        
        with open(NOTIFICATIONS_PATH, 'w') as f:
            json.dump(notifications, f, indent=2)
    
    return jsonify({'success': True})


@app.route('/api/circle/<code>/invite')
def get_invite(code):
    """Get invite link info."""
    circle = get_circle(code)
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404
    
    return jsonify({
        'code': code,
        'name': circle['name'],
        'member_count': len(circle['members']),
        'invite_path': f"/join/{code}"
    })


def init_data_files():
    """Initialize data files if they don't exist."""
    try:
        print(f"📁 Data directory: {DATA_DIR}")
        print(f"   STATE_PATH: {STATE_PATH}")
        print(f"   CIRCLES_PATH: {CIRCLES_PATH}")
        
        if not os.path.exists(STATE_PATH):
            save_state({"noshow_events": [], "available_users": {}})
            print("   Created state.json")
        
        if not os.path.exists(CIRCLES_PATH):
            save_circles({"circles": []})
            print("   Created circles.json")
        
        print("✅ Data files initialized successfully")
    except Exception as e:
        print(f"⚠️ Error initializing data files: {e}")
        # Don't crash - the app can still work with in-memory fallbacks
        pass

# Initialize on import (for gunicorn)
init_data_files()

if __name__ == '__main__':
    print("🎯 Roleplay Circles")
    print("   Open http://localhost:5050 to create a circle")
    app.run(debug=False, port=5050, host='0.0.0.0', threaded=True)
