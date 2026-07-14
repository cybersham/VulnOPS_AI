from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime ,ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer,primary_key=True, index=True)
    cve_id= Column(String,unique=True,index=True)
    description=Column(Text)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)            # LOW / MEDIUM / HIGH / CRITICAL
    published_date = Column(DateTime, nullable=True)
    is_kev = Column(Boolean, default=False) 

    findings = relationship("Findings", back_populates="cve")

class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)                  # e.g. "vulnops-api"
    owner = Column(String)                              # e.g. "cybersham"
    url = Column(String)

    findings = relationship("Findings" ,back_populates="repository")

class Findings(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id"))
    repository_id = Column(Integer, ForeignKey("repositories.id"))

    affected_package = Column(String)                  # e.g. "python-multipart"
    affected_version = Column(String)                  # e.g. "0.0.5"
    status = Column(String, default="open")            # open / fixed / ignored
    detected_date = Column(DateTime, default=datetime.utcnow)

    cve = relationship("CVE", back_populates="findings") ####This establishes a bidirectional (two-way) relationship. It tells SQLAlchemy that the CVE model has a corresponding attribute named findings that points back to this model
    repository = relationship("Repository", back_populates="findings") 



