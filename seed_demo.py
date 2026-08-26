"""Seed realistic demo member profiles for Dheeraja Matrimony."""
import os
import uuid
from datetime import datetime, timezone

import bcrypt
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

PW = bcrypt.hashpw(b"Demo@1234", bcrypt.gensalt()).decode()
NOW = datetime.now(timezone.utc)

MEMBERS = [
    ("Ananya Sharma", "female", "1998-04-12", "Hindu", "Brahmin", "Hindi", "Delhi", "Delhi", 160, "MBA", "Marketing Manager", "₹10-15 LPA", "Family-oriented, loves classical music and travel."),
    ("Priya Iyer", "female", "1996-09-23", "Hindu", "Iyer", "Tamil", "Tamil Nadu", "Chennai", 158, "B.Tech", "Software Engineer", "₹15-20 LPA", "Carnatic vocalist, working at a product company."),
    ("Sneha Patel", "female", "1997-01-30", "Hindu", "Patel", "Gujarati", "Gujarat", "Ahmedabad", 162, "CA", "Chartered Accountant", "₹10-15 LPA", "Balanced mix of traditional and modern values."),
    ("Fatima Khan", "female", "1999-07-08", "Muslim", "Sunni", "Urdu", "Uttar Pradesh", "Lucknow", 155, "M.Sc", "Lecturer", "₹5-10 LPA", "Teacher who loves poetry and calligraphy."),
    ("Simran Kaur", "female", "1995-11-17", "Sikh", "Jat", "Punjabi", "Punjab", "Chandigarh", 165, "MBBS", "Doctor", "₹15-20 LPA", "Pediatrician, close-knit family, loves cooking."),
    ("Meera Nair", "female", "1997-06-02", "Hindu", "Nair", "Malayalam", "Kerala", "Kochi", 159, "M.Des", "UX Designer", "₹10-15 LPA", "Design thinker, yoga enthusiast."),
    ("Arjun Mehta", "male", "1993-03-19", "Hindu", "Vaishya", "Hindi", "Maharashtra", "Mumbai", 178, "MBA", "Product Manager", "₹20-30 LPA", "Fitness enthusiast working in fintech."),
    ("Rohan Deshpande", "male", "1992-12-05", "Hindu", "Maratha", "Marathi", "Maharashtra", "Pune", 175, "B.Tech", "Senior Developer", "₹15-20 LPA", "Trekker and amateur photographer."),
    ("Imran Sheikh", "male", "1994-08-21", "Muslim", "Sunni", "Urdu", "Telangana", "Hyderabad", 172, "M.Tech", "Data Scientist", "₹20-30 LPA", "Analytics professional, foodie, family first."),
    ("Gurpreet Singh", "male", "1991-05-14", "Sikh", "Ramgarhia", "Punjabi", "Punjab", "Amritsar", 180, "B.Com", "Business Owner", "₹30+ LPA", "Runs a family export business."),
    ("Karthik Reddy", "male", "1993-10-28", "Hindu", "Reddy", "Telugu", "Telangana", "Hyderabad", 174, "MS (USA)", "Cloud Architect", "₹30+ LPA", "Recently moved back to India, loves cricket."),
    ("Joseph Thomas", "male", "1994-02-09", "Christian", "Syrian Catholic", "Malayalam", "Kerala", "Thiruvananthapuram", 176, "MBA", "Bank Manager", "₹10-15 LPA", "Church-going, calm, enjoys long drives."),
]


def calc_age(dob: str) -> int:
    d = datetime.strptime(dob, "%Y-%m-%d")
    t = datetime.now()
    return t.year - d.year - ((t.month, t.day) < (d.month, d.day))


created = 0
for full_name, gender, dob, religion, community, tongue, state, city, height, edu, occ, income, about in MEMBERS:
    email = full_name.lower().replace(" ", ".") + "@example.com"
    if db.users.find_one({"email": email}):
        continue
    user_id = str(uuid.uuid4())
    db.users.insert_one({
        "user_id": user_id, "email": email, "password_hash": PW,
        "role": "member", "status": "active", "created_at": NOW,
    })
    prof = {
        "user_id": user_id,
        "profile_id": f"DM{uuid.uuid4().hex[:8].upper()}",
        "email": email,
        "phone": "+91 98" + uuid.uuid4().hex[:8],
        "full_name": full_name,
        "gender": gender,
        "dob": dob,
        "age": calc_age(dob),
        "height_cm": height,
        "marital_status": "never_married",
        "religion": religion,
        "community": community,
        "mother_tongue": tongue,
        "country": "India",
        "state": state,
        "city": city,
        "education": edu,
        "occupation": occ,
        "income_range": income,
        "about_me": about,
        "family_details": "Close-knit, well-settled family.",
        "profile_visibility": True,
        "verified": False,
        "privacy": {"show_email": False, "show_phone": False, "show_photos": True},
        "photo_ids": [],
        "created_at": NOW,
        "last_active": NOW,
    }
    filled = sum(1 for v in prof.values() if v not in (None, "", []))
    prof["completeness"] = min(95, int(filled * 4))
    db.profiles.insert_one(prof)
    created += 1

# mark a few as verified for demo
for name in ["Ananya Sharma", "Arjun Mehta", "Simran Kaur", "Karthik Reddy"]:
    db.profiles.update_one({"full_name": name}, {"$set": {"verified": True}})

print(f"Seeded {created} demo members (password: Demo@1234). Total members: {db.users.count_documents({'role': 'member'})}")
