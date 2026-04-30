from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime

class BaseMessage(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        protected_namespaces=()
    )
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class RawEvent(BaseMessage):
    """Schema for data coming from Suricata socket."""
    event_type: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = Field(alias="proto")
    flow_id: Optional[int] = None
    packet_count: Optional[int] = 0
    byte_count: Optional[int] = 0
    alert_signature: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)

class FlowAggregate(BaseMessage):
    """Schema for aggregated flow data passed to ML."""
    event_type: str = "flow"
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    packet_count: int
    byte_count: int
    pps: float  # Packets per second
    bps: float  # Bytes per second
    features: Optional[List[float]] = Field(default=None, description="Normalized 77-feature vector")

class AlertPayload(BaseMessage):
    """Schema for final processed alerts sent to UI."""
    event_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    prediction: str  # attack, suspicious, normal
    confidence: float
    category: str
    alert_sig: str
    final_score: float
    model_version: str
    latency_ms: Dict[str, float] = Field(default_factory=dict)
    reputation_delta: float = 0.0

class SystemStatus(BaseModel):
    """Schema for periodic health heartbeats."""
    component: str
    status: str = "ok"
    uptime_sec: float
    processed_count: int
    error_count: int
    queue_depth: int
    extra: Dict[str, Any] = Field(default_factory=dict)
