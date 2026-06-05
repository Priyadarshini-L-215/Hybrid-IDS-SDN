from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Dict, Optional, List

class NetworkConfig(BaseModel):
    api_port: int = Field(3000, ge=1, le=65535)
    redis_host: str = Field("127.0.0.1")
    redis_port: int = Field(6379, ge=1, le=65535)

class DecisionEngineThresholds(BaseModel):
    attack: float = Field(0.9, ge=0.0, le=1.0)
    suspicious: float = Field(0.7, ge=0.0, le=1.0)
    anomaly: float = Field(0.6, ge=0.0, le=1.0)

class DecisionEngineWeights(BaseModel):
    signature: float = Field(1.0, ge=0.0, le=1.0)
    ml: float = Field(0.7, ge=0.0, le=1.0)
    anomaly: float = Field(0.3, ge=0.0, le=1.0)

class DecisionEngineConfig(BaseModel):
    thresholds: DecisionEngineThresholds
    weights: DecisionEngineWeights

class DetectionConfig(BaseModel):
    autoencoder_threshold: float = Field(0.04, gt=0)
    anomaly_min_samples: int = Field(10, ge=1)
    correlation_window: float = Field(10.0, gt=0)
    decision_engine: DecisionEngineConfig
    dos_threshold: int = Field(100, ge=1)
    ml: Dict[str, str] = Field(default_factory=lambda: {"active_model": "rf_model.pkl", "active_scaler": "scaler.pkl"})
    port_scan_threshold: int = Field(25, ge=1)

class MitigationConfig(BaseModel):
    block_ttl: int = Field(300, ge=0)
    rate_limit_per_sec: int = Field(5, ge=1)
    reputation_limit: float = Field(10.0, ge=0)
    reputation_temp_block: float = Field(25.0, ge=0)
    reputation_perm_block: float = Field(50.0, ge=0)
    ebpf_enabled: bool = Field(False)
    ebpf_interface: str = Field("eth0")
    quarantine_vlan_id: int = Field(99, ge=1, le=4094)

    @model_validator(mode='after')
    def validate_reputation_tiers(self):
        if not (self.reputation_limit <= self.reputation_temp_block <= self.reputation_perm_block):
            raise ValueError("Reputation thresholds must be ascending: limit <= temp_block <= perm_block")
        return self

class SystemConfig(BaseModel):
    batch_flush_interval: float = Field(0.25, gt=0)
    batch_size: int = Field(20, ge=1)
    log_level: str = Field("INFO")
    use_json_logging: bool = Field(False)
    worker_count: int = Field(8, ge=1, le=32)

    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v: str):
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return v.upper()

class ForensicsConfig(BaseModel):
    pcap_enabled: bool = Field(True)

class SentinelConfig(BaseModel):
    detection: DetectionConfig
    mitigation: MitigationConfig
    network: NetworkConfig
    system: SystemConfig
    forensics: ForensicsConfig
