"""
Pydantic models for Certificate management.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class CertificateSigningRequestCreate(BaseModel):
    """Model for creating a Certificate Signing Request (CSR)"""
    subject_CN: str = Field(..., description="Common Name (e.g., server.example.com)")
    subject_O: Optional[str] = Field(None, description="Organization (e.g., Example Inc.)")
    subject_OU: Optional[str] = Field(None, description="Organizational Unit (e.g., IT Department)")
    subject_L: Optional[str] = Field(None, description="Locality/City (e.g., San Francisco)")
    subject_ST: Optional[str] = Field(None, description="State/Province (e.g., California)")
    subject_C: Optional[str] = Field(None, description="Country (2-letter code, e.g., US)")
    subject_SAN: Optional[str] = Field(None, description="Subject Alternative Names (comma-separated, e.g., dns:alt.example.com,ip:192.168.1.1)")
    private_key_password: str = Field(..., description="Password for the private key")
    private_key_type: str = Field(default="RSA-2048", description="Private key type (e.g., RSA-2048, ECDSA-P256)")
    digest_algorithm: str = Field(default="sha256", description="Digest algorithm (e.g., sha256, sha384, sha512, md5)")


class CertificateSigningRequest(CertificateSigningRequestCreate):
    """Model representing a created Certificate Signing Request"""
    id: int
    csr_pem: Optional[str] = Field(None, description="The CSR in PEM format")
    # Add other relevant fields returned by the API


class CertificateTrustListEntry(BaseModel):
    """Model for an entry in the Certificate Trust List"""
    id: int
    issuer: Optional[str] = None
    subject: Optional[str] = None
    serial: Optional[str] = None
    thumbprint: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    alias_name: Optional[str] = None
    enabled: Optional[bool] = None
    usage: Optional[List[str]] = None # e.g., ["EAP", "SAML", "Others"]


class CertificateTrustListImport(BaseModel):
    """Model for importing a certificate to the Trust List"""
    cert_file: str = Field(..., description="Certificate content in PEM format (Base64 encoded or plain text)")
    cert_usage: List[str] = Field(..., description="Usage of the certificate, from the appliance vocabulary: 'EAP', 'Others', 'SAML', 'SMTP', 'AD/LDAP Servers', 'Aruba Services', 'Aruba Infrastructure', 'Endpoint Context Servers', 'RadSec', 'Database' (e.g., ['Others'])."),
    enabled: bool = Field(default=True, description="Enable this certificate in the trust list")
    # alias_name: Optional[str] = Field(None, description="Optional alias name for the certificate") # Seems not directly supported by new_cert_trust_list in pyclearpass


class ClientCertificate(BaseModel):
    """Model for a Client Certificate"""
    id: int
    subject: Optional[str] = None
    issuer: Optional[str] = None
    thumbprint: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    # Add other relevant fields from pyclearpass get_client_cert_by_client_cert_id


class ClientCertificateImport(BaseModel):
    """Model for importing a new Client Certificate"""
    # Based on new_client_cert in pyclearpass
    certificate_url: Optional[str] = Field(None, description="URL to the certificate file (e.g., from an Onboard CA).")
    pkcs12_file_url: Optional[str] = Field(None, description="URL to the PKCS12 file.")
    pkcs12_passphrase: Optional[str] = Field(None, description="Passphrase for the PKCS12 file.")
    # It seems new_client_cert might also allow direct upload, but the pyclearpass model example is sparse.
    # For now, focusing on URL based on the pyclearpass body example.
    # If direct content upload is needed, this model and the tool will need adjustment.


class ServerCertificate(BaseModel):
    """Model for a Server Certificate summary (from get_server_cert)"""
    service_id: Optional[str] = Field(None, description="Service ID associated with the certificate (e.g., 'eap', 'https', 'radsec')")
    cn: Optional[str] = Field(None, description="Common Name of the certificate")
    server_uuid: Optional[str] = Field(None, description="UUID of the server if applicable")
    # get_server_cert in pyclearpass seems to return a list of such objects directly, not nested under _embedded.


class ServerCertificateDetail(BaseModel):
    """Model for detailed Server Certificate information"""
    id: Optional[str] = None # Or int, need to check API response
    service_id: Optional[str] = None
    server_uuid: Optional[str] = None
    cn: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    thumbprint: Optional[str] = None
    pem: Optional[str] = Field(None, description="Certificate content in PEM format")
    # Add other fields from get_server_cert_by_service_id or get_server_cert_name_by_server_uuid_service_name


class ServiceCertificate(BaseModel):
    """Model for a Service Certificate"""
    id: int
    service_name: Optional[str] = None # e.g., PolicyManager_EAP_Certificate
    thumbprint: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    # Add other relevant fields from get_service_cert_by_service_cert_id