"""
Pydantic models for Local Server Configuration management.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ServerAccessControl(BaseModel):
    """Model for Server Access Control configuration"""
    access: str = Field(..., description="Access type of the Access control application (e.g., 'Allow', 'Deny')")
    networks: Dict[str, Any] = Field(..., description="Hostname, IP address or subnet (CIDR) of the Networks to be restricted")
    resource_name: Optional[str] = Field(None, description="Unique resource name of the access control")


class ADDomain(BaseModel):
    """Model for Active Directory Domain information"""
    domain_controller: Optional[str] = Field(None, description="FQDN of the domain controller")
    netbios_name: str = Field(..., description="NetBIOS name of the domain")
    username: Optional[str] = Field(None, description="Domain username")
    password: Optional[str] = Field(None, description="Domain password")
    on_name_conflict: Optional[int] = Field(None, description="Action to perform in case of a controller name conflict (1-3)")
    force_leave: Optional[bool] = Field(None, description="Leave domain even if AD is down")


class ADDomainJoin(BaseModel):
    """Model for joining an AD Domain"""
    domain_controller: str = Field(..., description="FQDN of the domain controller")
    netbios_name: str = Field(..., description="NetBIOS name of the domain")
    on_name_conflict: int = Field(..., description="Action to perform in case of a controller name conflict (1 - Use specified DC, 2 - Use DNS returned DC, 3 - Fail on conflict)")
    username: str = Field(..., description="Domain username")
    password: str = Field(..., description="Domain password")


class ADDomainLeave(BaseModel):
    """Model for leaving an AD Domain"""
    netbios_name: str = Field(..., description="NetBIOS name of the domain")
    username: str = Field(..., description="Domain username")
    password: str = Field(..., description="Domain password")
    force_leave: bool = Field(default=False, description="Leave domain even if AD is down")


class ADPasswordServersConfig(BaseModel):
    """Model for configuring AD Password Servers"""
    netbios_name: str = Field(..., description="NetBIOS name of the domain")
    password_servers: List[str] = Field(..., description="List of Hostname or IP Address of the AD password servers")


class ClusterServer(BaseModel):
    """Model for Cluster Server information"""
    uuid: Optional[str] = Field(None, description="UUID of the server")
    hostname: Optional[str] = Field(None, description="Hostname of the server")
    management_ip: Optional[str] = Field(None, description="Management IP address")
    is_master: Optional[bool] = Field(None, description="Whether this server is the master")
    status: Optional[str] = Field(None, description="Server status")


class ServerSNMPConfig(BaseModel):
    """Model for Server SNMP Configuration"""
    enabled: bool = Field(default=False, description="Enable SNMP")
    version: Optional[str] = Field(None, description="SNMP version (v1, v2c, v3)")
    community_string: Optional[str] = Field(None, description="SNMP community string")
    contact: Optional[str] = Field(None, description="SNMP contact information")
    location: Optional[str] = Field(None, description="SNMP location information")


class ServiceParameter(BaseModel):
    """Model for Service Parameter configuration"""
    service_id: str = Field(..., description="Service ID")
    parameters: Dict[str, Any] = Field(..., description="Service parameters in key-value format")


class ServerService(BaseModel):
    """Model for Server Service information"""
    service_name: str = Field(..., description="Name of the service")
    status: Optional[str] = Field(None, description="Service status (running, stopped, etc.)")
    enabled: Optional[bool] = Field(None, description="Whether service is enabled")


class ServerVersion(BaseModel):
    """Model for Server Version information"""
    version: Optional[str] = Field(None, description="ClearPass version")
    build: Optional[str] = Field(None, description="Build number")
    release_date: Optional[str] = Field(None, description="Release date") 