from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

class BaseMessage(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        protected_namespaces=()
    )
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))

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
    features: Optional[List[float]] = Field(default=None, description="Normalized 49-feature vector (UNSW-NB15 schema)")

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


# ---------------------------------------------------------------------------
# API Response Models
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Response for GET /api/health."""
    status: str
    timestamp: str


class AlertSummary(BaseModel):
    """Compact alert representation in list responses."""
    id: Optional[int] = None
    event_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    prediction: Optional[str] = None
    confidence: Optional[float] = None
    category: Optional[str] = None
    alert_sig: Optional[str] = None
    final_score: Optional[float] = None
    timestamp: Optional[str] = None

    model_config = {"extra": "allow"}


class AlertsResponse(BaseModel):
    """Response for GET /api/alerts."""
    alerts: List[AlertSummary]
    total_processed: int = 0
    attack_total: int = 0
    normal_total: int = 0
    displayed_total: int = 0
    error: Optional[str] = None


class BaselineStatsDetail(BaseModel):
    mean: float = 0.0
    std: float = 0.0


class BaselineStatusResponse(BaseModel):
    """Response for GET /api/baseline/status."""
    is_calibrated: bool
    drift_detected: bool
    last_refresh: str
    accuracy_pct: float
    last_trained: str
    model_version: str
    baseline_stats: BaselineStatsDetail


class MLEngineStatus(BaseModel):
    status: str
    ready: bool

    model_config = {"extra": "allow"}


class PipelineChecks(BaseModel):
    consumer_running: bool
    redis_ok: bool
    ws_port_open: bool


class PipelineStatsDetail(BaseModel):
    processed_total: int = 0
    attacks: int = 0
    normal: int = 0


class PipelineStatusResponse(BaseModel):
    """Response for GET /api/pipeline/status."""
    status: str
    ml_engine: Dict[str, Any]
    redis_ok: bool
    queue_depth: int
    stats: PipelineStatsDetail
    ipset: Dict[str, Any]
    ipset_detailed: Dict[str, Any]
    checks: PipelineChecks


class PipelineStatusSlimResponse(BaseModel):
    """Response for GET /api/pipeline/status/slim."""
    status: str
    ml_engine: str
    consumer: str
    blocked_count: int = 0
    ts: float
    trace_id: str


class MitigationResult(BaseModel):
    """Response for POST /api/mitigation/* endpoints."""
    success: bool
    message: str


class NodeIntelligenceResponse(BaseModel):
    """Response for GET /api/intelligence/node/{ip}."""
    ip: str
    alert_count: int = 0
    recent_activity: List[Any] = Field(default_factory=list)
    reputation_score: int = 0
    is_mitigated: bool = False
    predictions: Dict[str, Any] = Field(default_factory=dict)
    top_signatures: List[Any] = Field(default_factory=list)
    geo: Dict[str, Any] = Field(default_factory=dict)
    cti: Dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    ja3_hash: Optional[str] = None
    lateral_movement_risk: List[Any] = Field(default_factory=list)
    error: Optional[str] = None

    model_config = {"extra": "allow"}
