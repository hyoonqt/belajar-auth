from faker import Faker
from sqlalchemy.orm import Session

from database import SessionLocal, engine, Base
from models import UserDB
from security import hash_password

fake = Faker("id_ID")

DUMMY_COUNT = 100


def seed_users(db: Session, count: int):
    users = []

    for i in range(count):
        email = f"dummy{i + 1}@example.com"
        password = "Password123!"

        user = UserDB(
            email=email,
            hashed_password=hash_password(password),
            name=fake.name(),
            role="admin" if i == 0 else "user",
            profile_picture=None,
            country="Indonesia",
            city=fake.city()
        )

        users.append(user)

    db.add_all(users)
    db.commit()

    print(f"[+] Created {len(users)} dummy users")
    print(f"[+] Default password: Password123!")


def main():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        seed_users(db, DUMMY_COUNT)
    finally:
        db.close()


if __name__ == "__main__":
    main()