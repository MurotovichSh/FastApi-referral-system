from sqlalchemy import Column, Integer, String
from database.database import Base
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    referral_code = Column(String, nullable=True)

    referrals= relationship("Referral", back_populates="referrer")
