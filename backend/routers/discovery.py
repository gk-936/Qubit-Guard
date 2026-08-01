"""
Discovery Router — API endpoints for asset discovery and pillar classification.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db import get_db
from services.discovery_service import discover_pnb_assets

router = APIRouter()

class DiscoveryRequest(BaseModel):
    target: str

@router.post("/")
def perform_discovery(body: DiscoveryRequest):
    """
    Triggers a discovery scan for a targeting domain (and its subdomains).
    Classifies assets across Triad pillars (Web/VPN/API).
    """
    result = discover_pnb_assets(body.target)
    return {"success": True, "data": result}
