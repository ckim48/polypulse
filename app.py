from flask import Flask, render_template, request, jsonify, flash,session,redirect,url_for
from openai import OpenAI
import pytesseract
from PIL import Image
import os
import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = '1234'
# Initialize OpenAI client
# OCR and analysis
@app.route('/image-upload', methods=['GET', 'POST'])
def image_upload():
    analysis = ""
    if request.method == 'POST':
        img = request.files['image']
        if img:
            path = os.path.join('static', img.filename)
            img.save(path)
            text = pytesseract.image_to_string(Image.open(path))
            analysis = gpt_analyze(text)
    return render_template('image_upload.html', analysis=analysis)
@app.route('/preview-ocr', methods=['POST'])
def preview_ocr():
    file = request.files.get('image')
    if not file:
        return jsonify({"error": "No image uploaded"}), 400

    path = os.path.join('static', file.filename)
    file.save(path)

    try:
        text = pytesseract.image_to_string(Image.open(path))
        os.remove(path)  # Optional: Clean up temp file
        return jsonify({"text": text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'warning')
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Fetch user information
    c.execute('SELECT name, username, role FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()

    # Fetch user's insights from the DB
    c.execute('SELECT original, category, explanation, suggestion FROM insights WHERE user_id = ?', (session['user_id'],))
    rows = c.fetchall()
    insights = [
        {
            "original": row[0],
            "category": row[1],
            "explanation": row[2],
            "suggestion": row[3]
        }
        for row in rows
    ]

    # Count categories for pie chart
    category_count = {}
    for item in insights:
        cat = item["category"]
        category_count[cat] = category_count.get(cat, 0) + 1

    # Most frequent category
    most_frequent = max(category_count.items(), key=lambda x: x[1])[0] if category_count else "N/A"

    # Happiness score (assume total lines = harmful lines + good lines)
    total_lines = len(insights) + session.get("good_lines", 0)  # optionally track "good" lines separately
    harmful_lines = len(insights)
    happiness_score = max(0, 100 - int((harmful_lines / total_lines) * 100)) if total_lines else 100

    conn.close()

    if user:
        return render_template(
            'profile.html',
            name=user[0],
            username=user[1],
            role=user[2],
            insights=insights,
            category_count=category_count,
            most_frequent=most_frequent,
            happiness_score=happiness_score
        )
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))


# Chat with GPT
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    messages = []
    if request.method == 'POST':
        user_input = request.form['message']
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a supportive emotional assistant for families."},
                {"role": "user", "content": user_input}
            ]
        )
        reply = response.choices[0].message.content
        messages = [(user_input, reply)]
    return render_template('chat.html', messages=messages)

@app.route('/analyze', methods=['GET'])
def analyze_page():
    if 'user_id' not in session:
        flash('Please log in to access the analysis tool.', 'warning')
        return redirect(url_for('login'))
    return render_template('analyze.html')

# Analyze multiple lines and return structured JSON (POST)
@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    results = []
    uploaded_file = request.files.get('file')
    input_text = request.form.get('message', '')

    if uploaded_file:
        filename = secure_filename(uploaded_file.filename)
        file_ext = os.path.splitext(filename)[1].lower()

        if file_ext in ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']:
            # Handle image with OCR
            image_path = os.path.join('static', filename)
            uploaded_file.save(image_path)
            ocr_text = pytesseract.image_to_string(Image.open(image_path))
            input_text += '\n' + ocr_text
        else:
            # Handle text file
            try:
                content = uploaded_file.read().decode('utf-8')
                input_text += '\n' + content
            except UnicodeDecodeError:
                return jsonify({"error": "Only text or supported image files are allowed."}), 400

    lines = [line.strip() for line in input_text.split('\n') if line.strip()]

    # Remove old analysis for the user
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM insights WHERE user_id = ?', (session['user_id'],))
    conn.commit()

    # Track good lines too (optional)
    good_lines = 0

    for line in lines:
        prompt = f"""
        You are an emotional communication expert.

        - Line: "{line}"
        Is this line harmful in a family setting? If so, explain why and suggest a healthier way to say it.

        Format:
        - Category: ...
        - Explanation: ...
        - Suggested Alternative: ...
        If the line is not harmful, respond with "- Category: None"
        """
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )

        raw = response.choices[0].message.content
        category = extract_section(raw, "Category")
        explanation = extract_section(raw, "Explanation")
        suggestion = extract_section(raw, "Suggested Alternative")

        if category and category.lower() != "none":
            results.append({
                "original": line,
                "category": category,
                "explanation": explanation,
                "suggestion": suggestion
            })

            # Store in database
            c.execute('''
                INSERT INTO insights (user_id, original, category, explanation, suggestion)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                line,
                category,
                explanation,
                suggestion
            ))
        else:
            good_lines += 1  # Track positive lines

    conn.commit()
    conn.close()

    session['good_lines'] = good_lines  # Store in session for happiness score (optional)
    return jsonify({"results": results})


# Helper function to extract structured parts from GPT output
def extract_section(text, keyword):
    for line in text.splitlines():
        if line.startswith(f"- {keyword}:"):
            return line.replace(f"- {keyword}:", "").strip()
    return ""

# Text analysis using GPT for OCR or bulk input
def gpt_analyze(text):
    prompt = f"""
    You are an emotional communication expert.

    Analyze the following multi-line message (which may contain multiple statements from a parent or a child).
    Identify only the lines that are emotionally harmful, judgmental, shaming, dismissive, or manipulative — especially in a family context.

    For each problematic line:
    - Quote the original line.
    - Explain why it's harmful.
    - Suggest a more emotionally supportive alternative for either the parent or the child.

    If a line is fine, ignore it.

    Text to analyze:
    {text}

    Format the output like this:
    - Line: "..."
    - Why it's harmful: ...
    - Better way to say it: ...
    """

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content

# Landing page
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)',
                      (name, username, hashed_password, role))
            conn.commit()
            conn.close()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose another.', 'danger')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']  # or `username`, depending on your form
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, name, password, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            session['role'] = user[3]
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Try again.', 'danger')

    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)