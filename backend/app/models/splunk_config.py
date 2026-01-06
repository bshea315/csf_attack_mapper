"""Splunk configuration model for ES and SOAR integration."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from app.models.database import Base


class SplunkConfig(Base):
    """
    Splunk connection configuration.

    Stores connection details for Splunk ES and SOAR log access.
    Sensitive fields (tokens, passwords) are stored encrypted.
    """
    __tablename__ = "splunk_config"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, default="default")

    # Connection settings
    base_url = Column(String(500), nullable=False)  # https://splunk-sh.company.com:8089
    auth_type = Column(String(20), nullable=False, default="token")  # 'token' or 'basic'
    auth_token_encrypted = Column(Text, nullable=True)  # Encrypted bearer token
    auth_username = Column(String(100), nullable=True)  # For basic auth
    auth_password_encrypted = Column(Text, nullable=True)  # Encrypted password
    verify_tls = Column(Boolean, default=True)

    # ES settings
    es_app_namespace = Column(String(100), default="SplunkEnterpriseSecuritySuite")
    es_owner = Column(String(100), default="nobody")

    # SOAR log settings
    soar_playbook_run_index = Column(String(100), default="phantom_playbook_run")
    soar_action_run_index = Column(String(100), default="phantom_action_run")
    soar_time_window_days = Column(Integer, default=30)

    # Status
    is_active = Column(Boolean, default=True)
    last_es_sync_at = Column(DateTime, nullable=True)
    last_soar_sync_at = Column(DateTime, nullable=True)
    es_detection_count = Column(Integer, default=0)
    soar_playbook_count = Column(Integer, default=0)
    soar_run_count = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<SplunkConfig(id={self.id}, name='{self.name}', url='{self.base_url}')>"
