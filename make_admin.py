from app import app, db
from models import User

with app.app_context():
    user = User.query.filter_by(email='cihe22804@student.cihe.edu.au').first()
    if user:
        user.is_admin = True
        db.session.commit()
        print("✅ User promoted to admin.")
    else:
        print("❌ User not found.")
