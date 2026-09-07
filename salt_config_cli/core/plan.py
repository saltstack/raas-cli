"""
Plan execution for Salt Config CLI.

Handles the plan/apply workflow similar to Terraform, including:
- Diffing current vs desired state
- Generating execution plans
- Applying changes to remote resources
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from salt_config_cli.core.models import Resource, ResourceType, ChangeAction
from salt_config_cli.core.state import StateManager, ResourceState


class ResourceChange(BaseModel):
    """Represents a planned change to a resource."""
    
    action: ChangeAction
    resource_type: Union[ResourceType, str]
    name: str
    
    # Before/after states
    before: Optional[Dict[str, Any]] = None
    after: Optional[Dict[str, Any]] = None
    
    # Detailed attribute changes
    attribute_changes: Dict[str, Tuple[Any, Any]] = Field(default_factory=dict)
    
    # Dependencies that must be applied first
    depends_on: List[str] = Field(default_factory=list)
    
    # Flags
    replace: bool = Field(default=False, description="Resource must be destroyed and recreated")
    sensitive: bool = Field(default=False, description="Contains sensitive values")
    
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
    
    def get_change_summary(self) -> str:
        """Get a human-readable summary of the change."""
        action_symbols = {
            ChangeAction.CREATE: "+",
            ChangeAction.UPDATE: "~",
            ChangeAction.DELETE: "-",
            ChangeAction.NO_OP: " ",
            ChangeAction.READ: "?",
        }
        symbol = action_symbols.get(self.action, "?")
        return f"{symbol} {self.resource_address}"


class Plan(BaseModel):
    """
    Execution plan containing all changes to be applied.
    
    Similar to Terraform's plan output.
    """
    
    # Plan metadata
    plan_id: str = Field(default="", description="Unique plan identifier")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Changes organized by action
    changes: List[ResourceChange] = Field(default_factory=list)
    
    # Summary counts
    to_create: int = 0
    to_update: int = 0
    to_delete: int = 0
    unchanged: int = 0
    
    # Outputs that will change
    output_changes: Dict[str, Tuple[Any, Any]] = Field(default_factory=dict)
    
    # Validation errors/warnings
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    @property
    def has_changes(self) -> bool:
        """Check if plan contains any changes."""
        return self.to_create > 0 or self.to_update > 0 or self.to_delete > 0
    
    @property
    def is_valid(self) -> bool:
        """Check if plan is valid (no errors)."""
        return len(self.errors) == 0
    
    def add_change(self, change: ResourceChange) -> None:
        """Add a change to the plan."""
        self.changes.append(change)
        
        # Update counts
        if change.action == ChangeAction.CREATE:
            self.to_create += 1
        elif change.action == ChangeAction.UPDATE:
            self.to_update += 1
        elif change.action == ChangeAction.DELETE:
            self.to_delete += 1
        elif change.action == ChangeAction.NO_OP:
            self.unchanged += 1
    
    def get_ordered_changes(self) -> List[ResourceChange]:
        """Get changes in dependency order."""
        # Simple topological sort based on depends_on
        ordered = []
        pending = list(self.changes)
        applied_addresses = set()
        
        max_iterations = len(pending) * 2
        iterations = 0
        
        while pending and iterations < max_iterations:
            iterations += 1
            for change in pending[:]:
                # Check if all dependencies are satisfied
                deps_satisfied = all(
                    dep in applied_addresses 
                    for dep in change.depends_on
                )
                if deps_satisfied:
                    ordered.append(change)
                    applied_addresses.add(change.resource_address)
                    pending.remove(change)
        
        # Add any remaining (circular deps) at the end
        ordered.extend(pending)
        return ordered
    
    def get_summary(self) -> str:
        """Get a summary of the plan."""
        parts = []
        if self.to_create > 0:
            parts.append(f"{self.to_create} to create")
        if self.to_update > 0:
            parts.append(f"{self.to_update} to update")
        if self.to_delete > 0:
            parts.append(f"{self.to_delete} to delete")
        if self.unchanged > 0:
            parts.append(f"{self.unchanged} unchanged")
        
        if not parts:
            return "No changes. Infrastructure is up-to-date."
        
        return f"Plan: {', '.join(parts)}."


class PlanExecutor:
    """
    Executes the plan/apply workflow.
    
    Responsible for:
    - Loading configuration files
    - Comparing desired vs current state
    - Generating execution plans
    - Applying changes via API
    """
    
    def __init__(
        self,
        state_manager: StateManager,
        api_client: Any = None,
        config_dir: str = "."
    ):
        self.state_manager = state_manager
        self.api_client = api_client
        self.config_dir = config_dir
        self._resource_handlers: Dict[ResourceType, "ResourceHandler"] = {}
    
    def register_handler(self, resource_type: ResourceType, handler: "ResourceHandler") -> None:
        """Register a handler for a resource type."""
        self._resource_handlers[resource_type] = handler
    
    def load_configuration(self) -> List[Resource]:
        """Load all resource configurations from config files."""
        import yaml
        from pathlib import Path
        
        resources = []
        config_path = Path(self.config_dir)
        
        # Load all .yaml and .yml files
        for pattern in ["*.yaml", "*.yml", "**/*.yaml", "**/*.yml"]:
            for file_path in config_path.glob(pattern):
                # Skip hidden files and directories
                if any(part.startswith('.') for part in file_path.parts):
                    continue
                
                try:
                    with open(file_path, "r") as f:
                        docs = list(yaml.safe_load_all(f))
                    
                    for doc in docs:
                        if doc and isinstance(doc, dict):
                            resource = self._parse_resource(doc, str(file_path))
                            if resource:
                                resources.append(resource)
                except Exception as e:
                    # Log warning but continue
                    pass
        
        return resources
    
    def _parse_resource(self, data: Dict[str, Any], source_file: str) -> Optional[Resource]:
        """Parse a resource from configuration data."""
        from salt_config_cli.core.models import ResourceMetadata, resource_factory
        
        # Expected format:
        # resource_type: target_group
        # metadata:
        #   name: web-servers
        #   description: Web server target group
        # spec:
        #   targets: [...]
        
        resource_type_str = data.get("resource_type")
        if not resource_type_str:
            return None
        
        try:
            resource_type = ResourceType(resource_type_str)
        except ValueError:
            return None
        
        metadata_data = data.get("metadata", {})
        if not metadata_data.get("name"):
            return None
        
        metadata = ResourceMetadata(**metadata_data)
        spec = data.get("spec", {})
        
        return resource_factory(
            resource_type=resource_type,
            metadata=metadata,
            spec=spec
        )
    
    def plan(self, target: Optional[str] = None, destroy: bool = False) -> Plan:
        """
        Generate an execution plan.
        
        Args:
            target: Optional resource address to target specifically
            destroy: If True, plan to destroy all resources
        
        Returns:
            Plan containing all changes to be made
        """
        import uuid
        
        plan = Plan(plan_id=str(uuid.uuid4())[:8])
        
        # Load desired configuration
        desired_resources = self.load_configuration()
        
        # Build lookup of desired resources by address
        desired_by_address = {
            f"{r.resource_type_value}.{r.metadata.name}": r
            for r in desired_resources
        }
        
        # Get current state
        current_resources = {
            rs.resource_address: rs
            for rs in self.state_manager.list_resources()
        }
        
        if destroy:
            # Plan to delete all resources in state
            for address, resource_state in current_resources.items():
                if target and address != target:
                    continue
                
                change = ResourceChange(
                    action=ChangeAction.DELETE,
                    resource_type=resource_state.resource_type,
                    name=resource_state.name,
                    before=resource_state.attributes,
                    after=None,
                )
                plan.add_change(change)
        else:
            # Compare desired vs current
            all_addresses = set(desired_by_address.keys()) | set(current_resources.keys())
            
            for address in all_addresses:
                if target and address != target:
                    continue
                
                desired = desired_by_address.get(address)
                current = current_resources.get(address)
                
                change = self._compute_change(desired, current)
                if change:
                    plan.add_change(change)
        
        return plan
    
    def _compute_change(
        self, 
        desired: Optional[Resource], 
        current: Optional[ResourceState]
    ) -> Optional[ResourceChange]:
        """Compute the change needed between desired and current state."""
        
        if desired is None and current is None:
            return None
        
        if desired is not None and current is None:
            # Create new resource
            return ResourceChange(
                action=ChangeAction.CREATE,
                resource_type=desired.resource_type,
                name=desired.metadata.name,
                before=None,
                after=desired.spec,
            )
        
        if desired is None and current is not None:
            # Delete resource (not in config anymore)
            return ResourceChange(
                action=ChangeAction.DELETE,
                resource_type=current.resource_type,
                name=current.name,
                before=current.attributes,
                after=None,
            )
        
        # Both exist - check for updates
        assert desired is not None and current is not None
        
        desired_spec = desired.spec
        current_attrs = current.attributes
        
        # Compute attribute differences
        attr_changes = {}
        all_keys = set(desired_spec.keys()) | set(current_attrs.keys())
        
        for key in all_keys:
            desired_val = desired_spec.get(key)
            current_val = current_attrs.get(key)
            if desired_val != current_val:
                attr_changes[key] = (current_val, desired_val)
        
        if attr_changes:
            return ResourceChange(
                action=ChangeAction.UPDATE,
                resource_type=desired.resource_type,
                name=desired.metadata.name,
                before=current_attrs,
                after=desired_spec,
                attribute_changes=attr_changes,
            )
        
        # No changes
        return ResourceChange(
            action=ChangeAction.NO_OP,
            resource_type=desired.resource_type,
            name=desired.metadata.name,
            before=current_attrs,
            after=desired_spec,
        )
    
    def apply(self, plan: Plan, auto_approve: bool = False) -> Dict[str, Any]:
        """
        Apply an execution plan.
        
        Args:
            plan: The plan to apply
            auto_approve: Skip confirmation prompt
        
        Returns:
            Dict with results of each change
        """
        results = {
            "success": [],
            "failed": [],
            "skipped": [],
        }
        
        if not plan.has_changes:
            return results
        
        # Get changes in dependency order
        ordered_changes = plan.get_ordered_changes()
        
        for change in ordered_changes:
            if change.action == ChangeAction.NO_OP:
                results["skipped"].append(change.resource_address)
                continue
            
            try:
                self._apply_change(change)
                results["success"].append(change.resource_address)
                
                # Update state
                if change.action == ChangeAction.DELETE:
                    self.state_manager.remove_resource(
                        change.resource_type, 
                        change.name
                    )
                else:
                    resource_state = ResourceState(
                        resource_type=change.resource_type,
                        name=change.name,
                        attributes=change.after or {},
                        updated_at=datetime.now(timezone.utc),
                    )
                    resource_state.config_hash = resource_state.compute_hash()
                    self.state_manager.set_resource(resource_state)
                
            except Exception as e:
                results["failed"].append({
                    "address": change.resource_address,
                    "error": str(e)
                })
        
        # Save state
        self.state_manager.save()
        
        return results
    
    def _apply_change(self, change: ResourceChange) -> None:
        """Apply a single change via API."""
        handler = self._resource_handlers.get(change.resource_type)
        
        if handler:
            if change.action == ChangeAction.CREATE:
                handler.create(self.api_client, change.name, change.after or {})
            elif change.action == ChangeAction.UPDATE:
                handler.update(self.api_client, change.name, change.after or {})
            elif change.action == ChangeAction.DELETE:
                handler.delete(self.api_client, change.name)
        else:
            # No handler - use generic API calls
            self._apply_generic(change)
    
    def _apply_generic(self, change: ResourceChange) -> None:
        """Apply change using generic API patterns."""
        if self.api_client is None:
            raise RuntimeError("No API client configured")
        
        # This will be implemented with actual API calls
        # For now, just log the intended action
        pass


class ResourceHandler:
    """Base class for resource-specific handlers."""
    
    resource_type: ResourceType
    
    def create(self, api_client: Any, name: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new resource."""
        raise NotImplementedError
    
    def read(self, api_client: Any, identifier: str) -> Optional[Dict[str, Any]]:
        """Read a resource from the server."""
        raise NotImplementedError
    
    def update(self, api_client: Any, name: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing resource."""
        raise NotImplementedError
    
    def delete(self, api_client: Any, name: str) -> None:
        """Delete a resource."""
        raise NotImplementedError
    
    def list(self, api_client: Any) -> List[Dict[str, Any]]:
        """List all resources of this type."""
        raise NotImplementedError
