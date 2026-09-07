"""
State management for Salt Config CLI.

Handles tracking the current state of managed resources, similar to
Terraform's state file management.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from salt_config_cli.core.models import Resource, ResourceType, ChangeAction


class ResourceState(BaseModel):
    """State of a single managed resource."""
    
    resource_type: ResourceType
    name: str
    uuid: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[str] = Field(default_factory=list)
    
    # Checksums for drift detection
    config_hash: Optional[str] = None
    remote_hash: Optional[str] = None
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @property
    def resource_address(self) -> str:
        """Get the full resource address."""
        return f"{self.resource_type.value}.{self.name}"
    
    def compute_hash(self) -> str:
        """Compute hash of current attributes for drift detection."""
        content = json.dumps(self.attributes, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def has_drift(self) -> bool:
        """Check if resource has drifted from remote state."""
        if self.config_hash and self.remote_hash:
            return self.config_hash != self.remote_hash
        return False


class StateFile(BaseModel):
    """
    State file containing all managed resources.
    
    Similar to Terraform's tfstate file format.
    """
    
    version: int = Field(default=1, description="State file format version")
    serial: int = Field(default=0, description="State serial number (increments on each change)")
    lineage: str = Field(default="", description="Unique identifier for this state's lineage")
    
    # Resources indexed by address (type.name)
    resources: Dict[str, ResourceState] = Field(default_factory=dict)
    
    # Outputs
    outputs: Dict[str, Any] = Field(default_factory=dict)
    
    # Metadata
    scc_version: str = Field(default="salt-config-cli/0.4.0")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def get_resource(self, resource_type: ResourceType, name: str) -> Optional[ResourceState]:
        """Get a resource by type and name."""
        address = f"{resource_type.value}.{name}"
        return self.resources.get(address)
    
    def set_resource(self, resource: ResourceState) -> None:
        """Add or update a resource in state."""
        self.resources[resource.resource_address] = resource
        self.updated_at = datetime.now(timezone.utc)
        self.serial += 1
    
    def remove_resource(self, resource_type: ResourceType, name: str) -> Optional[ResourceState]:
        """Remove a resource from state."""
        address = f"{resource_type.value}.{name}"
        if address in self.resources:
            removed = self.resources.pop(address)
            self.updated_at = datetime.now(timezone.utc)
            self.serial += 1
            return removed
        return None
    
    def list_resources(self, resource_type: Optional[ResourceType] = None) -> List[ResourceState]:
        """List all resources, optionally filtered by type."""
        resources = list(self.resources.values())
        if resource_type:
            resources = [r for r in resources if r.resource_type == resource_type]
        return resources


class StateManager:
    """
    Manages state persistence and synchronization.
    
    Supports local file storage and can be extended to support
    remote backends (S3, GCS, etc.).
    """
    
    def __init__(
        self,
        state_path: str = ".scc/salt.state",
        backend: str = "local",
        lock_timeout: int = 60
    ):
        self.state_path = Path(state_path)
        self.backend = backend
        self.lock_timeout = lock_timeout
        self._state: Optional[StateFile] = None
        self._lock_file: Optional[Path] = None
    
    @property
    def state(self) -> StateFile:
        """Get current state, loading from disk if necessary."""
        if self._state is None:
            self._state = self.load()
        return self._state
    
    def load(self) -> StateFile:
        """Load state from backend."""
        if self.backend == "local":
            return self._load_local()
        else:
            raise NotImplementedError(f"Backend '{self.backend}' not yet supported")
    
    def _load_local(self) -> StateFile:
        """Load state from local file."""
        if self.state_path.exists():
            try:
                with open(self.state_path, "r") as f:
                    data = json.load(f)
                return StateFile(**data)
            except (json.JSONDecodeError, Exception) as e:
                # Backup corrupted state and start fresh
                backup_path = self.state_path.with_suffix(".state.backup")
                if self.state_path.exists():
                    self.state_path.rename(backup_path)
                return self._create_new_state()
        return self._create_new_state()
    
    def _create_new_state(self) -> StateFile:
        """Create a new empty state file."""
        import uuid
        return StateFile(
            lineage=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    def save(self) -> None:
        """Save state to backend."""
        if self.backend == "local":
            self._save_local()
        else:
            raise NotImplementedError(f"Backend '{self.backend}' not yet supported")
    
    def _save_local(self) -> None:
        """Save state to local file."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temp file first, then atomic rename
        temp_path = self.state_path.with_suffix(".state.tmp")
        with open(temp_path, "w") as f:
            json.dump(
                self.state.model_dump(mode="json"),
                f,
                indent=2,
                default=str
            )
        
        # Backup existing state
        if self.state_path.exists():
            backup_path = self.state_path.with_suffix(".state.backup")
            self.state_path.rename(backup_path)
        
        # Atomic rename
        temp_path.rename(self.state_path)
    
    def lock(self) -> bool:
        """Acquire state lock."""
        if self.backend == "local":
            return self._lock_local()
        return True
    
    def _lock_local(self) -> bool:
        """Acquire local file lock."""
        self._lock_file = self.state_path.with_suffix(".state.lock")
        try:
            if self._lock_file.exists():
                # Check if lock is stale
                lock_age = datetime.now(timezone.utc).timestamp() - self._lock_file.stat().st_mtime
                if lock_age > self.lock_timeout:
                    self._lock_file.unlink()
                else:
                    return False
            
            self._lock_file.parent.mkdir(parents=True, exist_ok=True)
            lock_info = {
                "pid": os.getpid(),
                "created": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._lock_file, "w") as f:
                json.dump(lock_info, f)
            return True
        except Exception:
            return False
    
    def unlock(self) -> None:
        """Release state lock."""
        if self._lock_file and self._lock_file.exists():
            self._lock_file.unlink()
    
    def refresh(self, api_client: Any) -> Dict[str, ChangeAction]:
        """
        Refresh state from remote server.
        
        Returns a dict of resource addresses to their drift status.
        """
        drift_report = {}
        
        for address, resource_state in self.state.resources.items():
            try:
                remote_resource = self._fetch_remote_resource(
                    api_client, 
                    resource_state.resource_type, 
                    resource_state.uuid or resource_state.name
                )
                
                if remote_resource is None:
                    # Resource was deleted remotely
                    drift_report[address] = ChangeAction.DELETE
                else:
                    # Compute hash of remote state
                    remote_hash = hashlib.sha256(
                        json.dumps(remote_resource, sort_keys=True, default=str).encode()
                    ).hexdigest()[:16]
                    
                    resource_state.remote_hash = remote_hash
                    
                    if resource_state.has_drift():
                        drift_report[address] = ChangeAction.UPDATE
                    else:
                        drift_report[address] = ChangeAction.NO_OP
                        
            except Exception as e:
                # Unable to fetch remote state
                drift_report[address] = ChangeAction.READ
        
        return drift_report
    
    def _fetch_remote_resource(
        self, 
        api_client: Any, 
        resource_type: ResourceType, 
        identifier: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch a resource from the remote server."""
        # This will be implemented by specific resource handlers
        # Placeholder for now
        return None
    
    def get_resource(self, resource_type: ResourceType, name: str) -> Optional[ResourceState]:
        """Get a resource from state."""
        return self.state.get_resource(resource_type, name)
    
    def set_resource(self, resource: ResourceState) -> None:
        """Add or update a resource in state."""
        self.state.set_resource(resource)
    
    def remove_resource(self, resource_type: ResourceType, name: str) -> Optional[ResourceState]:
        """Remove a resource from state."""
        return self.state.remove_resource(resource_type, name)
    
    def list_resources(self, resource_type: Optional[ResourceType] = None) -> List[ResourceState]:
        """List all resources in state."""
        return self.state.list_resources(resource_type)
