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
    epss_score = Column(Float, nullable=True)  # 0.0-1.0, probability of exploitation in next 30 days

    findings = relationship("Findings", back_populates="cve")

class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)                  # e.g. "vulnops-api"
    owner = Column(String)                              # e.g. "cybersham"
    url = Column(String)
    business_criticality = Column(Integer, default=3)  # 1-5 scale, 5 = most critical
    internet_exposed = Column(Boolean, default=True)
    compensating_controls = Column(Integer, default=1)  # 1-5 scale, 5 = well-mitigated

    findings = relationship("Findings" ,back_populates="repository")

# class Findings(Base):
#     __tablename__ = "findings"
#     id = Column(Integer, primary_key=True, index=True)
#     cve_id = Column(Integer, ForeignKey("cves.id"))
#     repository_id = Column(Integer, ForeignKey("repositories.id"))

#     affected_package = Column(String)                  # e.g. "python-multipart"
#     affected_version = Column(String)                  # e.g. "0.0.5"
#     status = Column(String, default="open")            # open / fixed / ignored
#     detected_date = Column(DateTime, default=datetime.utcnow)

#     cve = relationship("CVE", back_populates="findings") ####This establishes a bidirectional (two-way) relationship. It tells SQLAlchemy that the CVE model has a corresponding attribute named findings that points back to this model
#     repository = relationship("Repository", back_populates="findings") 



class Findings(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id"))
    repository_id = Column(Integer, ForeignKey("repositories.id"))

    affected_package = Column(String)
    affected_version = Column(String)
    status = Column(String, default="open")
    source = Column(String, default="dependabot")  # "dependabot" or "trivy"
    detected_date = Column(DateTime, default=datetime.utcnow)

    cve = relationship("CVE", back_populates="findings")
    repository = relationship("Repository", back_populates="findings")
