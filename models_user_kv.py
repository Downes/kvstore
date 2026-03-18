# models_user_kv.py — SQLAlchemy models for per-user kvstore databases
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    auth_hash = Column(String(200), nullable=False)   # bcrypt(auth_hash from client)
    api_token_hash = Column(String(64), nullable=True)  # sha256(opaque_token)
    token_expires = Column(DateTime, nullable=True)


class KeyValue(Base):
    __tablename__ = 'key_values'
    id = Column(Integer, primary_key=True)
    key = Column(String(200), unique=True, nullable=False)
    value = Column(Text, nullable=False)
