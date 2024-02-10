from sqlalchemy import Column, Integer, String, ForeignKey,DateTime
from database.database import Base
from sqlalchemy.orm import relationship
from .user import User

class Referral(Base):
    __tablename__ = "referrals"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)
    expiration_date = Column(DateTime)
    referrer_id = Column(Integer,ForeignKey("users.id"))
    referrer_email = Column(String)

    referrer = relationship("User", back_populates="referrals")
