"""
Drift detection and remediation for Salt Config CLI.

This module handles:
- Fetching current state from RaaS server
- Comparing against expected/desired state from YAML configs
- Identifying drift (differences)
- Generating remediation plans
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from salt_config_cli.core.models import Resource, ResourceType


class DriftStatus(str, Enum):
    """Status of drift detection for a resource."""
    
    IN_SYNC = "in_sync"           # Resource matches expected state
    DRIFTED = "drifted"           # Resource exists but differs from expected
    MISSING = "missing"           # Resource expected but not found on server
    UNEXPECTED = "unexpected"     # Resource on server but not in config (orphaned)
    UNKNOWN = "unknown"           # Unable to determine status


class DriftSeverity(str, Enum):
    """Severity level of detected drift."""
    
    INFO = "info"           # Minor differences, informational
    WARNING = "warning"     # Significant drift, should be reviewed
    CRITICAL = "critical"   # Critical drift, immediate remediation needed


class AttributeDrift(BaseModel):
    """Represents drift in a single attribute."""
    
    attribute: str
    expected_value: Any
    actual_value: Any
    severity: DriftSeverity = DriftSeverity.WARNING
    
    @property
    def description(self) -> str:
        return f"{self.attribute}: expected '{self.expected_value}', found '{self.actual_value}'"


class ResourceDrift(BaseModel):
    """Represents drift detected in a resource."""
    
    resource_type: Union[ResourceType, str]
    name: str
    status: DriftStatus
    severity: DriftSeverity = DriftSeverity.WARNING
    
    # Expected vs actual state
    expected_state: Optional[Dict[str, Any]] = None
    actual_state: Optional[Dict[str, Any]] = None
    
    # Detailed attribute-level drift
    attribute_drifts: List[AttributeDrift] = Field(default_factory=list)
    
    # Metadata
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message: Optional[str] = None
    job_id: Optional[str] = None
    
    @property
    def resource_type_value(self) -> str:
        """Get the resource type as a string."""
        if isinstance(self.resource_type, ResourceType):
            return self.resource_type.value
        return str(self.resource_type)
    
    @property
    def resource_address(self) -> str:
        """Get the full resource address."""
        return f"{self.resource_type_value}.{self.name}"
    
    @property
    def has_drift(self) -> bool:
        """Check if resource has any drift."""
        return self.status in (DriftStatus.DRIFTED, DriftStatus.MISSING, DriftStatus.UNEXPECTED)
    
    @property
    def drift_summary(self) -> str:
        """Get a summary of the drift."""
        if self.status == DriftStatus.IN_SYNC:
            return "✓ In sync"
        elif self.status == DriftStatus.MISSING:
            return "✗ Missing from server"
        elif self.status == DriftStatus.UNEXPECTED:
            return "? Unexpected (not in config)"
        elif self.status == DriftStatus.DRIFTED:
            return f"~ Drifted ({len(self.attribute_drifts)} attribute(s))"
        return "? Unknown"


class DriftReport(BaseModel):
    """Complete drift detection report."""
    
    # Report metadata
    report_id: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    server_url: Optional[str] = None
    
    # Results
    resources: List[ResourceDrift] = Field(default_factory=list)
    
    # Summary counts
    total_checked: int = 0
    in_sync: int = 0
    drifted: int = 0
    missing: int = 0
    unexpected: int = 0
    
    @property
    def has_drift(self) -> bool:
        """Check if any drift was detected."""
        return self.drifted > 0 or self.missing > 0 or self.unexpected > 0
    
    @property
    def overall_status(self) -> DriftStatus:
        """Get overall status of the report."""
        if not self.has_drift:
            return DriftStatus.IN_SYNC
        return DriftStatus.DRIFTED
    
    def add_resource(self, drift: ResourceDrift) -> None:
        """Add a resource drift result to the report."""
        self.resources.append(drift)
        self.total_checked += 1
        
        if drift.status == DriftStatus.IN_SYNC:
            self.in_sync += 1
        elif drift.status == DriftStatus.DRIFTED:
            self.drifted += 1
        elif drift.status == DriftStatus.MISSING:
            self.missing += 1
        elif drift.status == DriftStatus.UNEXPECTED:
            self.unexpected += 1
    
    def get_summary(self) -> str:
        """Get a summary of the drift report."""
        parts = []
        if self.in_sync > 0:
            parts.append(f"{self.in_sync} in sync")
        if self.drifted > 0:
            parts.append(f"{self.drifted} drifted")
        if self.missing > 0:
            parts.append(f"{self.missing} missing")
        if self.unexpected > 0:
            parts.append(f"{self.unexpected} unexpected")
        
        if not self.has_drift:
            return "All resources are in sync."
        
        return f"Drift detected: {', '.join(parts)}"
    
    def get_resources_needing_remediation(self) -> List[ResourceDrift]:
        """Get resources that need remediation."""
        return [r for r in self.resources if r.has_drift]


class RemediationAction(str, Enum):
    """Types of remediation actions."""
    
    SYNC = "sync"           # Sync resource to expected state
    CREATE = "create"       # Create missing resource
    DELETE = "delete"       # Remove unexpected resource
    SKIP = "skip"           # Skip remediation


class RemediationItem(BaseModel):
    """A single remediation action to take."""
    
    resource_drift: ResourceDrift
    action: RemediationAction
    description: str
    
    # For selective remediation
    selected: bool = True
    
    @property
    def resource_address(self) -> str:
        return self.resource_drift.resource_address


class RemediationPlan(BaseModel):
    """Plan for remediating detected drift."""
    
    plan_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Source drift report
    drift_report: Optional[DriftReport] = None
    
    # Remediation items
    items: List[RemediationItem] = Field(default_factory=list)
    
    @property
    def to_sync(self) -> int:
        return sum(1 for i in self.items if i.action == RemediationAction.SYNC and i.selected)
    
    @property
    def to_create(self) -> int:
        return sum(1 for i in self.items if i.action == RemediationAction.CREATE and i.selected)
    
    @property
    def to_delete(self) -> int:
        return sum(1 for i in self.items if i.action == RemediationAction.DELETE and i.selected)
    
    @property
    def has_actions(self) -> bool:
        return any(i.selected for i in self.items if i.action != RemediationAction.SKIP)
    
    def get_summary(self) -> str:
        """Get summary of remediation plan."""
        parts = []
        if self.to_sync > 0:
            parts.append(f"{self.to_sync} to sync")
        if self.to_create > 0:
            parts.append(f"{self.to_create} to create")
        if self.to_delete > 0:
            parts.append(f"{self.to_delete} to delete")
        
        if not parts:
            return "No remediation needed."
        
        return f"Remediation plan: {', '.join(parts)}"


class ProgressCallback:
    """Callback interface for reporting drift detection progress."""
    
    def on_resource_start(self, resource_name: str, resource_type: str) -> None:
        """Called when starting to check a resource."""
        pass
    
    def on_job_submitted(self, resource_name: str, job_id: str) -> None:
        """Called when a Salt job is submitted."""
        pass
    
    def on_job_polling(self, resource_name: str, job_id: str, elapsed_seconds: int) -> None:
        """Called during job polling."""
        pass
    
    def on_job_complete(self, resource_name: str, job_id: str, elapsed_seconds: int) -> None:
        """Called when a job completes."""
        pass
    
    def on_resource_complete(self, resource_name: str, status: str) -> None:
        """Called when resource check completes."""
        pass


class DriftDetector:
    """
    Detects drift between expected configuration and actual server state.
    """
    
    def __init__(self, api_client: Any = None, progress_callback: Optional[ProgressCallback] = None):
        self.api_client = api_client
        self._handlers: Dict[str, Any] = {}
        self.progress_callback = progress_callback
    
    def register_handler(self, resource_type: ResourceType, handler: Any) -> None:
        """Register a handler for a resource type."""
        self._handlers[resource_type.value] = handler
    
    def detect(
        self,
        expected_resources: List[Resource],
        check_unexpected: bool = True
    ) -> DriftReport:
        """
        Detect drift between expected and actual state.
        
        Args:
            expected_resources: List of resources from YAML config
            check_unexpected: Also check for resources on server not in config
        
        Returns:
            DriftReport with all detected drift
        """
        import uuid
        
        report = DriftReport(
            report_id=str(uuid.uuid4())[:8],
            server_url=getattr(self.api_client, 'server', None) if self.api_client else None
        )
        
        # Group expected resources by type
        expected_by_type: Dict[str, List[Resource]] = {}
        for resource in expected_resources:
            rtype = resource.resource_type_value
            if rtype not in expected_by_type:
                expected_by_type[rtype] = []
            expected_by_type[rtype].append(resource)
        
        # Check each expected resource
        for resource in expected_resources:
            drift = self._check_resource(resource)
            report.add_resource(drift)
        
        # Optionally check for unexpected resources on server
        if check_unexpected and self.api_client:
            unexpected = self._find_unexpected_resources(expected_resources)
            for drift in unexpected:
                report.add_resource(drift)
        
        return report
    
    def _notify_resource_start(self, name: str, resource_type: str) -> None:
        """Notify progress callback that resource check is starting."""
        if self.progress_callback:
            self.progress_callback.on_resource_start(name, resource_type)
    
    def _notify_job_submitted(self, name: str, job_id: str) -> None:
        """Notify progress callback that a job was submitted."""
        if self.progress_callback:
            self.progress_callback.on_job_submitted(name, job_id)
    
    def _notify_job_polling(self, name: str, job_id: str, elapsed: int) -> None:
        """Notify progress callback during job polling."""
        if self.progress_callback:
            self.progress_callback.on_job_polling(name, job_id, elapsed)
    
    def _notify_job_complete(self, name: str, job_id: str, elapsed: int) -> None:
        """Notify progress callback that job completed."""
        if self.progress_callback:
            self.progress_callback.on_job_complete(name, job_id, elapsed)
    
    def _notify_resource_complete(self, name: str, status: str) -> None:
        """Notify progress callback that resource check completed."""
        if self.progress_callback:
            self.progress_callback.on_resource_complete(name, status)
    
    def _check_resource(self, expected: Resource) -> ResourceDrift:
        """Check a single resource for drift."""
        resource_type = expected.resource_type_value
        name = expected.metadata.name
        
        self._notify_resource_start(name, resource_type)
        
        # If no API client, we can't check actual state
        if not self.api_client:
            return ResourceDrift(
                resource_type=resource_type,
                name=name,
                status=DriftStatus.UNKNOWN,
                message="No API client configured - cannot verify actual state"
            )
        
        # Special handling for minion_state - runs state.apply --test
        if resource_type == "minion_state":
            return self._check_minion_state(expected)
        
        # Fetch actual state from server
        actual_state = self._fetch_actual_state(resource_type, name)
        
        if actual_state is None:
            # Resource doesn't exist on server
            return ResourceDrift(
                resource_type=resource_type,
                name=name,
                status=DriftStatus.MISSING,
                severity=DriftSeverity.WARNING,
                expected_state=expected.spec,
                actual_state=None,
                message=f"Resource not found on server"
            )
        
        # Compare expected vs actual
        attribute_drifts = self._compare_attributes(expected.spec, actual_state)
        
        if not attribute_drifts:
            return ResourceDrift(
                resource_type=resource_type,
                name=name,
                status=DriftStatus.IN_SYNC,
                severity=DriftSeverity.INFO,
                expected_state=expected.spec,
                actual_state=actual_state
            )
        
        # Determine severity based on drifted attributes
        max_severity = max(d.severity for d in attribute_drifts)
        
        return ResourceDrift(
            resource_type=resource_type,
            name=name,
            status=DriftStatus.DRIFTED,
            severity=max_severity,
            expected_state=expected.spec,
            actual_state=actual_state,
            attribute_drifts=attribute_drifts,
            message=f"{len(attribute_drifts)} attribute(s) differ from expected"
        )
    
    def _resolve_target_group(self, target_group_name: str) -> tuple:
        """
        Resolve a target group name to its target and target_type.
        
        Returns:
            Tuple of (target, target_type) or (None, None) if not found.
        """
        try:
            # API method is "get_target_group" (singular, no 's')
            resp = self.api_client.call("tgt", "get_target_group")
            if not resp.success or not resp.ret:
                return None, None
            
            ret = resp.ret
            if isinstance(ret, dict) and "results" in ret:
                groups = ret["results"]
            elif isinstance(ret, list):
                groups = ret
            else:
                groups = [ret]
            
            for g in groups:
                if isinstance(g, dict) and g.get("name", "").lower() == target_group_name.lower():
                    tgt_spec = g.get("tgt", {})
                    if isinstance(tgt_spec, dict):
                        for master_key, master_tgt in tgt_spec.items():
                            if isinstance(master_tgt, dict):
                                return master_tgt.get("tgt"), master_tgt.get("tgt_type", "glob")
            return None, None
        except Exception:
            return None, None
    
    def _check_minion_state(self, expected: Resource) -> ResourceDrift:
        """
        Check minion state drift by running state.apply in test mode.
        
        This runs the state against target minions and analyzes the output
        to determine if there would be any changes (drift).
        """
        import time
        
        name = expected.metadata.name
        spec = expected.spec
        
        # Extract state configuration
        state_file = spec.get("state_file", "")
        state_files = spec.get("state_files", [state_file] if state_file else [])
        
        # Check for target_group first, then fall back to target
        target_group_name = spec.get("target_group")
        if target_group_name:
            resolved_target, resolved_target_type = self._resolve_target_group(target_group_name)
            if resolved_target is None:
                return ResourceDrift(
                    resource_type="minion_state",
                    name=name,
                    status=DriftStatus.UNKNOWN,
                    message=f"Target group not found: {target_group_name}"
                )
            target = resolved_target
            target_type = resolved_target_type
        else:
            target = spec.get("target", "*")
            target_type = spec.get("target_type", "glob")
        
        saltenv = spec.get("environment", "base")
        pillar_data = spec.get("pillar", {})
        
        if not state_files:
            return ResourceDrift(
                resource_type="minion_state",
                name=name,
                status=DriftStatus.UNKNOWN,
                message="No state_file specified in configuration"
            )
        
        # Normalize state references (remove leading / and .sls extension)
        state_refs = []
        for sf in state_files:
            ref = sf.lstrip("/")
            if ref.endswith(".sls"):
                ref = ref[:-4]
            state_refs.append(ref)
        
        # Build target specification
        tgt_spec = {
            "*": {
                "tgt": target,
                "tgt_type": target_type
            }
        }
        
        # Build arg specification with test=True
        cmd_kwargs = {"saltenv": saltenv, "test": True}
        if pillar_data:
            cmd_kwargs["pillar"] = pillar_data
        
        arg_spec = {
            "arg": state_refs,
            "kwarg": cmd_kwargs
        }
        
        try:
            # Run state.apply in test mode
            resp = self.api_client.call(
                "cmd", "route_cmd",
                cmd="local",
                fun="state.apply",
                tgt=tgt_spec,
                arg=arg_spec
            )
            
            if resp.error:
                self._notify_resource_complete(name, "error")
                return ResourceDrift(
                    resource_type="minion_state",
                    name=name,
                    status=DriftStatus.UNKNOWN,
                    message=f"Failed to check state: {resp.error.get('message', 'Unknown error')}"
                )
            
            # Get job ID and wait for completion
            jid = resp.ret if isinstance(resp.ret, str) else resp.ret.get("jid") if isinstance(resp.ret, dict) else str(resp.ret)
            
            # Notify that job was submitted
            self._notify_job_submitted(name, jid)
            
            # Wait for job to complete
            max_wait = 120
            poll_interval = 2
            waited = 0
            completed = False
            
            while waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval
                
                # Notify polling progress
                self._notify_job_polling(name, jid, waited)
                
                status_resp = self.api_client.call("cmd", "get_cmd_status", jids=[jid])
                if status_resp.success and status_resp.ret:
                    status = status_resp.ret[0] if isinstance(status_resp.ret, list) else status_resp.ret
                    if isinstance(status, str) and status in ("complete", "completed"):
                        completed = True
                        break
                    elif isinstance(status, dict) and status.get("state") in ("complete", "completed"):
                        completed = True
                        break
            
            if completed:
                self._notify_job_complete(name, jid, waited)
            
            if not completed:
                self._notify_resource_complete(name, "timeout")
                return ResourceDrift(
                    resource_type="minion_state",
                    name=name,
                    status=DriftStatus.UNKNOWN,
                    message=f"Timeout waiting for state.apply --test (job: {jid})"
                )
            
            # Get results
            returns_resp = self.api_client.call("ret", "get_returns", jid=jid)
            if not returns_resp.success or not returns_resp.ret:
                self._notify_resource_complete(name, "error")
                return ResourceDrift(
                    resource_type="minion_state",
                    name=name,
                    status=DriftStatus.UNKNOWN,
                    message="Failed to get state results"
                )
            
            # Analyze results for drift
            result = self._analyze_minion_state_results(name, spec, returns_resp.ret, jid)
            self._notify_resource_complete(name, result.status.value)
            return result
            
        except Exception as e:
            self._notify_resource_complete(name, "error")
            return ResourceDrift(
                resource_type="minion_state",
                name=name,
                status=DriftStatus.UNKNOWN,
                message=f"Error checking minion state: {str(e)}"
            )
    
    def _analyze_minion_state_results(
        self,
        name: str,
        spec: Dict[str, Any],
        results: Dict[str, Any],
        jid: Optional[str] = None
    ) -> ResourceDrift:
        """Analyze state.apply --test results to determine drift."""
        
        # Parse results
        if isinstance(results, dict):
            minion_results = results.get("results", [])
        elif isinstance(results, list):
            minion_results = results
        else:
            minion_results = []
        
        if not minion_results:
            return ResourceDrift(
                resource_type="minion_state",
                name=name,
                status=DriftStatus.UNKNOWN,
                message="No minion results returned"
            )
        
        # Collect drift information across all minions
        total_states = 0
        states_in_sync = 0
        states_would_change = 0
        states_failed = 0
        attribute_drifts = []
        actual_state = {"minions": {}}
        
        for ret in minion_results:
            minion_id = ret.get("minion_id", ret.get("id", "unknown"))
            has_errors = ret.get("has_errors", False)
            
            # Get return data
            return_data = ret.get("return")
            if return_data is None:
                return_data = ret.get("full_ret", {}).get("return")
            if return_data is None:
                return_data = ret.get("ret", {})
            
            minion_states = {"in_sync": [], "would_change": [], "failed": []}
            
            if has_errors:
                states_failed += 1
                minion_states["failed"].append("Error executing state")
            elif isinstance(return_data, dict):
                for state_id, state_result in return_data.items():
                    if not isinstance(state_result, dict):
                        continue
                    
                    total_states += 1
                    result_val = state_result.get("result")
                    changes = state_result.get("changes", {})
                    comment = state_result.get("comment", "")
                    state_name = state_result.get("name", state_id)
                    
                    # Parse state ID for display
                    parts = state_id.split("_|-")
                    if len(parts) >= 4:
                        display_name = f"{parts[0]}.{parts[3]}: {parts[1]}"
                    else:
                        display_name = state_id[:50]
                    
                    if result_val is True and not changes:
                        # In sync
                        states_in_sync += 1
                        minion_states["in_sync"].append(display_name)
                    elif result_val is None:
                        # Test mode - would change (this indicates drift)
                        states_would_change += 1
                        minion_states["would_change"].append(display_name)
                        
                        # Extract actual change details from changes dict
                        change_details = self._format_changes(changes, comment)
                        
                        # Record as attribute drift with actual change info
                        attribute_drifts.append(AttributeDrift(
                            attribute=f"{minion_id}/{display_name}",
                            expected_value=change_details.get("expected", "configured"),
                            actual_value=change_details.get("actual", comment or "would change"),
                            severity=DriftSeverity.WARNING
                        ))
                    elif result_val is True and changes:
                        # Would change (in test mode with changes)
                        states_would_change += 1
                        minion_states["would_change"].append(display_name)
                    elif result_val is False:
                        # Failed
                        states_failed += 1
                        minion_states["failed"].append(f"{display_name}: {comment[:50]}")
                        
                        attribute_drifts.append(AttributeDrift(
                            attribute=f"{minion_id}/{display_name}",
                            expected_value="success",
                            actual_value=f"failed: {comment[:30]}",
                            severity=DriftSeverity.CRITICAL
                        ))
            
            actual_state["minions"][minion_id] = minion_states
        
        # Determine overall status
        actual_state["summary"] = {
            "total_states": total_states,
            "in_sync": states_in_sync,
            "would_change": states_would_change,
            "failed": states_failed
        }
        
        if states_failed > 0:
            return ResourceDrift(
                resource_type="minion_state",
                name=name,
                status=DriftStatus.DRIFTED,
                severity=DriftSeverity.CRITICAL,
                expected_state=spec,
                actual_state=actual_state,
                attribute_drifts=attribute_drifts,
                message=f"{states_failed} state(s) failed, {states_would_change} would change",
                job_id=jid
            )
        elif states_would_change > 0:
            return ResourceDrift(
                resource_type="minion_state",
                name=name,
                status=DriftStatus.DRIFTED,
                severity=DriftSeverity.WARNING,
                expected_state=spec,
                actual_state=actual_state,
                attribute_drifts=attribute_drifts,
                message=f"{states_would_change} state(s) would change on {len(minion_results)} minion(s)",
                job_id=jid
            )
        else:
            return ResourceDrift(
                resource_type="minion_state",
                name=name,
                status=DriftStatus.IN_SYNC,
                severity=DriftSeverity.INFO,
                expected_state=spec,
                actual_state=actual_state,
                message=f"All {states_in_sync} state(s) in sync on {len(minion_results)} minion(s)",
                job_id=jid
            )
    
    def _format_changes(self, changes: Dict[str, Any], comment: str = "") -> Dict[str, str]:
        """
        Extract and format change details from Salt state changes dict.
        
        Salt modules return different change structures:
        - file.managed: {'diff': '--- old\\n+++ new', 'newfile': '/path'}
        - file.absent: {'removed': '/path'}
        - pkg.installed: {'old': '', 'new': 'package-1.0'}
        - service.running: {'old': 'stopped', 'new': 'running'}
        - Generic: {'old': value, 'new': value} or {'before': value, 'after': value}
        """
        if not changes:
            return {"expected": "configured", "actual": comment or "would change"}
        
        # Handle file diff (most common for file.managed)
        if "diff" in changes:
            diff = changes["diff"]
            if isinstance(diff, str) and diff.strip():
                # Truncate very long diffs but show meaningful content
                diff_lines = diff.strip().split("\n")
                if len(diff_lines) > 20:
                    truncated = "\n".join(diff_lines[:20]) + f"\n... ({len(diff_lines) - 20} more lines)"
                    return {"expected": "file content", "actual": f"diff:\n{truncated}"}
                return {"expected": "file content", "actual": f"diff:\n{diff.strip()}"}
        
        # Handle new file creation
        if "newfile" in changes:
            return {"expected": "file exists", "actual": f"file would be created: {changes['newfile']}"}
        
        # Handle file removal
        if "removed" in changes:
            return {"expected": "file absent", "actual": f"file would be removed: {changes['removed']}"}
        
        # Handle old/new pattern (packages, services, etc.)
        if "old" in changes and "new" in changes:
            old_val = changes["old"]
            new_val = changes["new"]
            # Format empty values more clearly
            old_display = repr(old_val) if old_val == "" else str(old_val) if old_val else "(none)"
            new_display = repr(new_val) if new_val == "" else str(new_val) if new_val else "(none)"
            return {"expected": new_display, "actual": old_display}
        
        # Handle before/after pattern
        if "before" in changes and "after" in changes:
            before = changes["before"] or "(none)"
            after = changes["after"] or "(none)"
            return {"expected": str(after), "actual": str(before)}
        
        # Handle mode changes (file permissions)
        if "mode" in changes:
            mode_change = changes["mode"]
            if isinstance(mode_change, str):
                return {"expected": "correct mode", "actual": f"mode: {mode_change}"}
        
        # Handle user/group changes
        if "user" in changes or "group" in changes:
            parts = []
            if "user" in changes:
                parts.append(f"user: {changes['user']}")
            if "group" in changes:
                parts.append(f"group: {changes['group']}")
            return {"expected": "correct ownership", "actual": ", ".join(parts)}
        
        # Generic fallback - show the changes dict structure
        if len(changes) == 1:
            key, value = next(iter(changes.items()))
            return {"expected": "configured", "actual": f"{key}: {value}"}
        
        # Multiple changes - format as key: value pairs
        change_strs = [f"{k}: {v}" for k, v in list(changes.items())[:5]]
        if len(changes) > 5:
            change_strs.append(f"... and {len(changes) - 5} more")
        return {"expected": "configured", "actual": "; ".join(change_strs)}
    
    def _fetch_actual_state(self, resource_type: str, name: str) -> Optional[Dict[str, Any]]:
        """Fetch actual state of a resource from the server."""
        handler = self._handlers.get(resource_type)
        
        if handler:
            try:
                return handler.read(self.api_client, name)
            except Exception:
                return None
        
        # Generic fetch based on resource type
        try:
            if resource_type == "target_group":
                response = self.api_client.call("tgt", "get_target_group", name=name)
            elif resource_type == "job":
                response = self.api_client.call("job", "get_job", name=name)
            elif resource_type == "pillar":
                response = self.api_client.call("pillar", "get_pillar", name=name)
            elif resource_type == "state_file":
                path = name if name.endswith(".sls") else f"{name}.sls"
                response = self.api_client.call("fs", "get_file", path=path)
            else:
                return None
            
            if response.success:
                return response.ret
            return None
        except Exception:
            return None
    
    def _compare_attributes(
        self,
        expected: Dict[str, Any],
        actual: Dict[str, Any]
    ) -> List[AttributeDrift]:
        """Compare attributes between expected and actual state."""
        drifts = []
        
        # Attributes to ignore in comparison
        ignore_keys = {
            "uuid", "id", "created_at", "modified_at", 
            "created_by", "modified_by", "version"
        }
        
        all_keys = set(expected.keys()) | set(actual.keys())
        
        for key in all_keys - ignore_keys:
            expected_val = expected.get(key)
            actual_val = actual.get(key)
            
            if not self._values_match(expected_val, actual_val):
                drifts.append(AttributeDrift(
                    attribute=key,
                    expected_value=expected_val,
                    actual_value=actual_val,
                    severity=self._determine_attribute_severity(key)
                ))
        
        return drifts
    
    def _values_match(self, expected: Any, actual: Any) -> bool:
        """Check if two values match (with some tolerance)."""
        if expected is None and actual is None:
            return True
        if expected is None or actual is None:
            return False
        
        # Handle list comparison (order-independent for some cases)
        if isinstance(expected, list) and isinstance(actual, list):
            if len(expected) != len(actual):
                return False
            # For simple lists, compare sorted
            try:
                return sorted(expected) == sorted(actual)
            except TypeError:
                return expected == actual
        
        return expected == actual
    
    def _determine_attribute_severity(self, attribute: str) -> DriftSeverity:
        """Determine severity based on attribute name."""
        critical_attrs = {"targets", "function", "enabled", "permissions"}
        warning_attrs = {"description", "labels", "tags"}
        
        if attribute.lower() in critical_attrs:
            return DriftSeverity.CRITICAL
        if attribute.lower() in warning_attrs:
            return DriftSeverity.INFO
        return DriftSeverity.WARNING
    
    def _find_unexpected_resources(
        self,
        expected_resources: List[Resource]
    ) -> List[ResourceDrift]:
        """Find resources on server that aren't in expected config."""
        unexpected = []
        
        # Build set of expected resource addresses
        expected_addresses = {
            f"{r.resource_type_value}.{r.metadata.name}"
            for r in expected_resources
        }
        
        # Check each resource type on server
        resource_types_to_check = ["target_group", "job"]  # Add more as needed
        
        for rtype in resource_types_to_check:
            try:
                if rtype == "target_group":
                    response = self.api_client.call("tgt", "get_target_group")
                elif rtype == "job":
                    response = self.api_client.call("job", "get_jobs")
                else:
                    continue
                
                if response.success and response.ret:
                    for item in response.ret:
                        name = item.get("name", item.get("id", "unknown"))
                        address = f"{rtype}.{name}"
                        
                        if address not in expected_addresses:
                            unexpected.append(ResourceDrift(
                                resource_type=rtype,
                                name=name,
                                status=DriftStatus.UNEXPECTED,
                                severity=DriftSeverity.INFO,
                                actual_state=item,
                                message="Resource exists on server but not in configuration"
                            ))
            except Exception:
                continue
        
        return unexpected
    
    def create_remediation_plan(self, report: DriftReport) -> RemediationPlan:
        """Create a remediation plan from a drift report."""
        import uuid
        
        plan = RemediationPlan(
            plan_id=str(uuid.uuid4())[:8],
            drift_report=report
        )
        
        for drift in report.resources:
            if drift.status == DriftStatus.IN_SYNC:
                continue
            
            if drift.status == DriftStatus.DRIFTED:
                plan.items.append(RemediationItem(
                    resource_drift=drift,
                    action=RemediationAction.SYNC,
                    description=f"Sync {drift.resource_address} to expected state"
                ))
            elif drift.status == DriftStatus.MISSING:
                plan.items.append(RemediationItem(
                    resource_drift=drift,
                    action=RemediationAction.CREATE,
                    description=f"Create missing resource {drift.resource_address}"
                ))
            elif drift.status == DriftStatus.UNEXPECTED:
                plan.items.append(RemediationItem(
                    resource_drift=drift,
                    action=RemediationAction.DELETE,
                    description=f"Remove unexpected resource {drift.resource_address}",
                    selected=False  # Don't auto-select deletions
                ))
        
        return plan
