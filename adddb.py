import sqlite3
from datetime import datetime, timedelta
import random

# Expanded and varied mock data
mock_data = [
    {
        "original": "Why can’t you be more like your sister?",
        "category": "Judgmental",
        "explanation": "This line compares siblings and can lead to feelings of inadequacy.",
        "suggestion": "I appreciate your strengths and want to help you grow in your own way.",
        "sentiment": "Negative"
    },
    {
        "original": "You never do anything right.",
        "category": "Shaming",
        "explanation": "It makes the person feel worthless and undermines self-esteem.",
        "suggestion": "Let’s figure out together how to improve this next time.",
        "sentiment": "Negative"
    },
    {
        "original": "That’s just nonsense, don’t talk like that.",
        "category": "Dismissive",
        "explanation": "It invalidates the speaker’s feelings or opinions.",
        "suggestion": "I hear what you're saying. Can you tell me more about that?",
        "sentiment": "Negative"
    },
    {
        "original": "I’m proud of you for trying your best.",
        "category": "Supportive",
        "explanation": "Encouraging statements reinforce positive behavior.",
        "suggestion": "Keep going, you're doing great.",
        "sentiment": "Positive"
    },
    {
        "original": "Let’s talk about what happened and how we can fix it.",
        "category": "Constructive",
        "explanation": "Constructive conversation promotes growth.",
        "suggestion": "What do you think we could do differently next time?",
        "sentiment": "Neutral"
    },
    {
        "original": "You’re always causing problems.",
        "category": "Blaming",
        "explanation": "Generalizing blame can create shame.",
        "suggestion": "Can we talk about what went wrong and how to make it better?",
        "sentiment": "Negative"
    },
    {
        "original": "Calm down, you’re overreacting.",
        "category": "Dismissive",
        "explanation": "Invalidates emotional experience.",
        "suggestion": "I want to understand what you're feeling — let’s talk.",
        "sentiment": "Negative"
    },
    {
        "original": "You’re just being sensitive.",
        "category": "Shaming",
        "explanation": "Dismisses and criticizes emotional responses.",
        "suggestion": "I hear you, and I want to understand your feelings better.",
        "sentiment": "Negative"
    }
]

user_id = 1  # Make sure this is the correct ID for 'testtest'
base_date = datetime.now() - timedelta(days=10)

conn = sqlite3.connect('users.db')
c = conn.cursor()

# Insert each line multiple times with different dates
for i in range(30):  # Generate 30 entries for variety
    entry = random.choice(mock_data)
    timestamp = (base_date + timedelta(days=random.randint(0, 10))).strftime('%Y-%m-%d %H:%M:%S')

    c.execute('''
        INSERT INTO insights (user_id, original, category, explanation, suggestion, timestamp, sentiment)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        entry["original"],
        entry["category"],
        entry["explanation"],
        entry["suggestion"],
        timestamp,
        entry["sentiment"]
    ))

conn.commit()
conn.close()

print("🎉 Rich mock insights added for 'testtest' with varied timestamps and sentiments.")
