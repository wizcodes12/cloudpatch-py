
from fastapi import FastAPI, Request, HTTPException, Depends, Query, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, JSONResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware

# Pydantic
from pydantic import BaseModel

# Typing
from typing import Optional, List, Dict

# HTTP and Network Related
import requests
import aiohttp
import asyncio
from urllib.parse import quote, urlparse
import socket
import ssl

# Data Processing and Utilities
import json
import base64
import os
import re
import magic  # You'll need to install python-magic-bin for Windows or python-magic for Unix
import logging
import secrets
import inspect
import ast
from datetime import datetime
import mimetypes
from io import BytesIO
import traceback

# Machine Learning and AI
import torch
from transformers import (
    AutoModelForSequenceClassification,
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    pipeline
)
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset
import pandas as pd
import random

# PDF Generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from dotenv import load_dotenv
import json
import re
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import aiohttp
from pydantic import BaseModel
import asyncio
import ipaddress
import urllib.parse
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional



load_dotenv()

# Add these imports at the top of your main.py file


# Create FixRequest model if you don't have it already


SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))


# Define the expected data model structure to show what's expected
class PDFReportData(BaseModel):
    api_url: str
    platform: str
    timestamp: Optional[str] = None
    error: Dict[str, Any]  # type, severity, message
    solution: Dict[str, Any]  # description, suggested_fixes
    additional_context: Dict[str, Any] = {}  # environment, performance_metrics, etc.


class FileContent(BaseModel):
    name: str
    path: str
    sha: str
    size: int
    url: str
    content: Optional[str]
    encoding: Optional[str]
    type: str
    apis_found: Optional[List[str]] = []
    scan_results: Optional[dict] = None

class RepoContent(BaseModel):
    name: str
    path: str
    type: str
    sha: str
    size: Optional[int]
    content: Optional[List[FileContent]] = None


class FixRequest(BaseModel):
    api_url: str
    fix_content: str


class ApiErrorDetail(BaseModel):
    error_type: str
    error_message: str
    stack_trace: Optional[str]
    line_number: Optional[int]
    code_snippet: Optional[str]
    potential_causes: List[str]
    suggested_fixes: List[str]
    severity: str
    timestamp: str
    additional_context: Dict

class ApiAnalysisResult(BaseModel):
    endpoint: str
    status_code: int
    response_time: float
    errors: List[ApiErrorDetail]
    security_issues: List[Dict]
    performance_metrics: Dict
    recommendations: List[str]






API_PATTERNS = [
    r'https?://[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+?/api/[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+',
    r'https?://api\.[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+',
    r'https?://[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+?/v[0-9]+/[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+',
    r'https?://[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+?/rest/[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+',
    # Add GraphQL endpoints
    r'https?://[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]+?/graphql[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=\s]*'
]


# Models
class ErrorRequest(BaseModel):
    error_message: str

class FixRequest(BaseModel):
    api_url: str
    fix_content: str
    repo_name: Optional[str] = None
    file_path: Optional[str] = None

class ApiCheckResponse(BaseModel):
    platform: str
    repo_name: Optional[str]
    file_path: Optional[str]
    error: Optional[str]
    solution: Optional[str]
    status: Optional[str]

# Initialize FastAPI
app = FastAPI(title="CloudPatch.ai API")
router = APIRouter()

app.include_router(router)


# Constants
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

MODEL_PATH = "./final_model"  # Changed to look in current directory

# Global variables for model and tokenizer
model = None
tokenizer = None

# Middleware
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY,
    max_age=24 * 60 * 60,
    same_site="lax",
    https_only=False
)
from io import BytesIO
from datetime import datetime
import traceback
import logging
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT

def create_pdf_report(data: PDFReportData) -> BytesIO:
    buffer = BytesIO()
    
    # Create the document template with slightly reduced margins for more content space
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=70,
        bottomMargin=50
    )
    
    # Define custom styles
    styles = getSampleStyleSheet()
    
    # Custom styles for CloudPatch.AI branding
    title_style = ParagraphStyle(
        'CloudPatchTitle',
        parent=styles['Heading1'],
        fontSize=16,
        alignment=TA_CENTER,
        spaceAfter=20,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CloudPatchSubtitle',
        parent=styles['Heading2'],
        fontSize=10,
        alignment=TA_CENTER,
        textColor=colors.darkgrey,
        spaceBefore=0,
        spaceAfter=25,
        fontName='Helvetica'
    )
    
    heading_style = ParagraphStyle(
        'CloudPatchHeading',
        parent=styles['Heading2'],
        fontSize=12,
        spaceBefore=15,
        spaceAfter=10,
        fontName='Helvetica-Bold',
        borderWidth=1,
        borderColor=colors.lightgrey,
        borderPadding=5,
        borderRadius=2
    )
    
    subheading_style = ParagraphStyle(
        'CloudPatchSubheading',
        parent=styles['Heading3'],
        fontSize=10,
        spaceBefore=8,
        spaceAfter=8,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'CloudPatchNormal',
        parent=styles['Normal'],
        fontSize=9,
        spaceAfter=5,
        fontName='Helvetica'
    )
    
    code_style = ParagraphStyle(
        'CloudPatchCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        spaceAfter=10,
        spaceBefore=10,
        backColor=colors.whitesmoke,
        borderPadding=7,
        borderWidth=1,
        borderColor=colors.lightgrey,
        borderRadius=2
    )
    
    metadata_style = ParagraphStyle(
        'CloudPatchMetadata',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.darkgrey,
        alignment=TA_RIGHT
    )
    
    # Content elements
    elements = []
    
    # CloudPatch.AI Logo and Title
    elements.append(Paragraph(f"CloudPatch.AI", title_style))
    elements.append(Paragraph(f"API Error Solution Report", subtitle_style))
    
    # Report metadata
    report_id = f"CP-{datetime.now().strftime('%Y%m%d')}-{str(hash(data.api_url))[-4:]}"
    metadata_text = f"Report ID: {report_id} | Generated: {data.timestamp}"
    elements.append(Paragraph(metadata_text, metadata_style))
    elements.append(Spacer(1, 25))
    
    # Summary section
    # elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
    
    # # Create a summary paragraph
    # error_type = data.error['type']
    # severity = data.error['severity']
    # summary_text = f"This report details a {severity.lower()} severity {error_type} error encountered in the API endpoint. " \
    #               f"The error was detected in the {data.additional_context.get('environment', 'production')} environment. " \
    #               f"CloudPatch.AI has analyzed the issue and provided a recommended solution."
    # elements.append(Paragraph(summary_text, normal_style))
    # elements.append(Spacer(1, 15))
    
    # Basic Information in a clean table
    elements.append(Paragraph("SYSTEM INFORMATION", heading_style))
    basic_info = [
        ["API Endpoint", data.api_url],
        ["Platform", data.platform],
        ["Environment", data.additional_context.get("environment", "Production")],
        ["Timestamp", data.timestamp],
    ]
    
    basic_table = Table(basic_info, colWidths=[120, 330])
    basic_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(basic_table)
    elements.append(Spacer(1, 20))
    
    # Error Details with improved formatting
    elements.append(Paragraph("ERROR DETAILS", heading_style))
    
    error_info = [
        ["Error Type", data.error['type']],
        ["Severity", data.error['severity']],
    ]
    
    error_table = Table(error_info, colWidths=[120, 330])
    error_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(error_table)
    elements.append(Spacer(1, 10))
    
    elements.append(Paragraph("Error Message:", subheading_style))
    elements.append(Paragraph(data.error['message'], code_style))
    elements.append(Spacer(1, 15))
    
    # Solution Section with better organization
    elements.append(Paragraph("SOLUTION", heading_style))
    elements.append(Paragraph("Recommended Fix:", subheading_style))
    elements.append(Paragraph(data.solution['description'], code_style))
    
    if data.solution.get('suggested_fixes'):
        elements.append(Paragraph("Implementation Steps:", subheading_style))
        
        # Create a numbered list for the steps
        for i, fix in enumerate(data.solution['suggested_fixes'], 1):
            elements.append(Paragraph(f"{i}. {fix}", normal_style))
    
    elements.append(Spacer(1, 20))
    
    # Performance Metrics with improved visualization
    if data.additional_context.get('performance_metrics'):
        elements.append(Paragraph("PERFORMANCE ANALYSIS", heading_style))
        
        metrics = data.additional_context['performance_metrics']
        metrics_data = [[key, str(value)] for key, value in metrics.items()]
        
        metrics_table = Table(metrics_data, colWidths=[200, 250])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 15))
    
    # Footer note
    footer_text = "This report was automatically generated by CloudPatch.AI's error analysis system. " \
                 "For additional support, please contact support@cloudpatch.ai"
    elements.append(Paragraph(footer_text, metadata_style))
    
    # Create the PDF with a custom first page and header/footer on all pages
    def add_page_number(canvas, doc):
        # Save canvas state
        canvas.saveState()
        
        # Footer with page numbers
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.darkgrey)
        page_num_text = f"Page {doc.page} of {doc.page}"  # This will be updated with correct total in the build
        canvas.drawRightString(540, 30, page_num_text)
        
        # Header with CloudPatch.AI logo text on pages after the first
        if doc.page > 1:
            canvas.setFont('Helvetica-Bold', 10)
            canvas.drawString(50, 760, "CloudPatch.AI")
            canvas.setFont('Helvetica', 8)
            canvas.drawString(150, 760, "API Error Solution Report")
            
            # Add a thin grey line under the header
            canvas.setStrokeColor(colors.lightgrey)
            canvas.line(50, 750, 545, 750)
        
        # Draw thin grey footer line
        canvas.setStrokeColor(colors.lightgrey)
        canvas.line(50, 50, 545, 50)
        
        # Restore canvas state
        canvas.restoreState()
    
    # Build PDF with page numbers
    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return buffer

@router.post("/api/generate-pdf-report")
async def generate_pdf_report(data: PDFReportData):
    try:
        # Create timestamp in a consistent format
        if not data.timestamp:
            data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        # Generate PDF
        pdf_buffer = create_pdf_report(data)
        
        # Create a more professional filename with CloudPatch.AI branding
        report_id = f"CP-{datetime.now().strftime('%Y%m%d')}-{str(hash(data.api_url))[-4:]}"
        filename = f"CloudPatch-API-Report-{report_id}.pdf"
        
        # Set appropriate headers for PDF download
        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
        
        # Log successful report generation
        logging.info(f"Generated PDF report {report_id} for API: {data.api_url}")
        
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers=headers
        )
        
    except Exception as e:
        error_details = str(e)
        error_trace = traceback.format_exc()
        
        # Enhanced error logging
        logging.error(f"PDF Generation Error: {error_details}")
        logging.debug(f"Error traceback: {error_trace}")
        
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Failed to generate CloudPatch.AI error report",
                "error": error_details,
                "report_id": f"CP-ERR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "traceback": error_trace if "debug" in data.additional_context else None
            }
        )


app.include_router(router, prefix="")

async def determine_hosting_environment(api_url: str) -> Dict[str, str]:
    """
    Determine where an API is hosted and relevant repository information.
    """
    parsed_url = urlparse(api_url)
    
    # Check for localhost/local environments
    if parsed_url.hostname in ['localhost', '127.0.0.1'] or parsed_url.hostname.startswith('192.168.'):
        return {
            "environment": "local",
            "can_fix": False,
            "message": "Cannot auto-fix locally hosted APIs. Please deploy to a remote repository first."
        }
    
    # Check for GitHub Pages or GitHub-hosted APIs
    github_patterns = [
        r'([a-zA-Z0-9-]+)\.github\.io/([a-zA-Z0-9-._]+)',
        r'raw\.githubusercontent\.com/([a-zA-Z0-9-]+)/([a-zA-Z0-9-._]+)',
        r'api\.github\.com/repos/([a-zA-Z0-9-]+)/([a-zA-Z0-9-._]+)'
    ]
    
    for pattern in github_patterns:
        match = re.search(pattern, api_url)
        if match:
            return {
                "environment": "github",
                "can_fix": True,
                "owner": match.group(1),
                "repo": match.group(2),
                "message": "GitHub-hosted API detected. Auto-fix available."
            }
    
    # Add other hosting platforms as needed
    return {
        "environment": "unknown",
        "can_fix": False,
        "message": "Auto-fix is only available for GitHub-hosted APIs currently."
    }




async def apply_github_fix(
    owner: str,
    repo: str,
    path: str,
    fix_content: str,
    token: str
) -> Dict:
    """
    Apply a fix to a GitHub-hosted file.
    """
    # Get the current file content and SHA
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    file_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    
    # Get current file
    response = requests.get(file_url, headers=headers)
    response.raise_for_status()
    current_file = response.json()
    
    # Create update
    update_data = {
        "message": "CloudPatch.ai: Applied automated API fix",
        "content": base64.b64encode(fix_content.encode()).decode(),
        "sha": current_file["sha"]
    }
    
    # Send update
    update_response = requests.put(file_url, headers=headers, json=update_data)
    update_response.raise_for_status()
    
    return {
        "success": True,
        "commit_url": update_response.json()["commit"]["html_url"]
    }



async def analyze_error_response(response_text: str, status_code: int) -> ApiErrorDetail:
    """
    Analyzes error responses from Node.js APIs and creates detailed error information.
    Handles various error formats including Express, Koa, Hapi, and raw Node.js errors.
    """
    
    try:
        # Try to parse response as JSON
        error_data = json.loads(response_text)
    except json.JSONDecodeError:
        # If not JSON, treat as plain text and look for common Node.js error patterns
        error_data = {"message": response_text}
        
        # Check for Node.js specific error patterns in plain text
        if "Error:" in response_text:
            error_parts = response_text.split("Error:", 1)
            if len(error_parts) > 1:
                error_data["error_type"] = error_parts[0].strip() + "Error"
                error_data["message"] = error_parts[1].strip()

    # Extract error message with fallbacks for different Node.js frameworks
    error_message = (
        error_data.get("message") or 
        error_data.get("error") or 
        error_data.get("msg") or 
        error_data.get("errorMessage") or 
        response_text
    )
    
    # Parse stack trace from various formats
    stack_trace = None
    if isinstance(error_data, dict):
        stack_trace = (
            error_data.get("stack") or 
            error_data.get("stacktrace") or 
            error_data.get("stackTrace") or
            error_data.get("trace")
        )
    
    # If stack trace is in the response text but not parsed as JSON
    if not stack_trace and "at " in response_text and ("/node_modules/" in response_text or ".js:" in response_text):
        stack_lines = []
        for line in response_text.split("\n"):
            if line.strip().startswith("at ") and (".js:" in line or ".ts:" in line):
                stack_lines.append(line.strip())
        if stack_lines:
            stack_trace = "\n".join(stack_lines)
    
    # Identify Node.js specific error types
    error_type, file_info, line_number, code_snippet = extract_error_details(error_message, stack_trace, status_code)
    
    # Get detailed info for Node.js errors
    potential_causes, suggested_fixes = get_nodejs_error_guidance(error_type, error_message, status_code)
    
    # Determine severity based on error type and status code
    severity = determine_severity(error_type, status_code)
    
    # Extract additional contextual information
    additional_context = {
        "status_code": status_code,
        "raw_response": response_text[:1000],  # Limit size of raw response
        "headers": error_data.get("headers", {}) if isinstance(error_data, dict) else {},
        "file_info": file_info,
        "framework_hints": detect_framework(response_text, error_data),
        "nodejs_version_hint": extract_nodejs_version_hint(response_text, error_data),
    }
    
    return ApiErrorDetail(
        error_type=error_type,
        error_message=error_message,
        stack_trace=stack_trace,
        line_number=line_number,
        code_snippet=code_snippet,
        potential_causes=potential_causes,
        suggested_fixes=suggested_fixes,
        severity=severity,
        timestamp=datetime.now().isoformat(),
        additional_context=additional_context
    )


def extract_error_details(error_message: str, stack_trace: Optional[str], status_code: int) -> Tuple[str, Optional[str], Optional[int], Optional[str]]:
    """Extract detailed error information from Node.js error messages and stack traces."""
    error_type = "UnknownError"
    file_info = None
    line_number = None
    code_snippet = None
    
    # Map HTTP status codes to error types
    status_code_map = {
        400: "BadRequestError",
        401: "UnauthorizedError",
        403: "ForbiddenError",
        404: "NotFoundError",
        405: "MethodNotAllowedError",
        408: "RequestTimeoutError",
        409: "ConflictError",
        413: "PayloadTooLargeError",
        422: "UnprocessableEntityError",
        429: "TooManyRequestsError",
        500: "InternalServerError",
        501: "NotImplementedError",
        502: "BadGatewayError",
        503: "ServiceUnavailableError",
        504: "GatewayTimeoutError"
    }
    
    # Common Node.js error keywords
    nodejs_error_patterns = {
        "TypeError": r"TypeError:",
        "ReferenceError": r"ReferenceError:",
        "SyntaxError": r"SyntaxError:",
        "RangeError": r"RangeError:",
        "URIError": r"URIError:",
        "EvalError": r"EvalError:",
        "AssertionError": r"AssertionError",
        "SystemError": r"SystemError:",
        "MongoError": r"MongoError:|MongoDB",
        "SequelizeError": r"SequelizeError|Sequelize",
        "MySQLError": r"MySQLError|MySQL|ER_",
        "PostgresError": r"PostgresError|Postgres|PG:",
        "ConnectionError": r"ECONNREFUSED|ETIMEDOUT|connection.*failed",
        "ValidationError": r"ValidationError|valid.*failed|invalid",
        "AuthenticationError": r"Authentication.*failed|auth.*error|invalid.*credentials",
        "AuthorizationError": r"Authorization.*failed|forbidden|not.*allowed",
        "NotFoundError": r"not.*found|ENOENT",
        "TimeoutError": r"timeout|ETIMEDOUT",
        "RateLimitError": r"rate.*limit|too many requests",
        "MemoryError": r"memory.*overflow|heap.*out|ENOMEM",
        "DiskError": r"disk.*full|ENOSPC",
        "FilesystemError": r"EACCES|permission.*denied|cannot.*access",
        "NetworkError": r"network|ENETUNREACH|ENOTFOUND",
        "JsonWebTokenError": r"jwt|token.*invalid|malformed.*token",
        "EnvironmentError": r"env|environment|EENV",
        "ConfigurationError": r"config|configuration",
    }
    
    # First, try to identify error from status code
    if status_code in status_code_map:
        error_type = status_code_map[status_code]
    
    # Then try to identify from error message
    for err_type, pattern in nodejs_error_patterns.items():
        if re.search(pattern, error_message, re.IGNORECASE) or (stack_trace and re.search(pattern, stack_trace, re.IGNORECASE)):
            error_type = err_type
            break
    
    # Express-specific errors
    if "express" in error_message.lower() or (stack_trace and "express" in stack_trace.lower()):
        if "route" in error_message.lower() and "not found" in error_message.lower():
            error_type = "ExpressRouteError"
        elif "middleware" in error_message.lower():
            error_type = "ExpressMiddlewareError"
    
    # Parse file and line information from stack trace
    if stack_trace:
        # Look for standard Node.js stack trace format
        file_line_match = re.search(r'at\s+(?:.*\s+\()?(?:.*?)([\/\\][\w\-. /\\]+\.(js|ts|jsx|tsx|mjs|cjs))(?::(\d+)(?::(\d+))?)?\)?', stack_trace)
        if file_line_match:
            file_info = file_line_match.group(1)
            line_number = int(file_line_match.group(3)) if file_line_match.group(3) else None
    
    # Extract code snippet from error message if available
    code_match = re.search(r'```(?:javascript|js|typescript|ts)?\n(.*?)\n```', error_message, re.DOTALL)
    if code_match:
        code_snippet = code_match.group(1)
    
    return error_type, file_info, line_number, code_snippet


def detect_framework(response_text: str, error_data: Dict) -> str:
    """Detect which Node.js framework is being used based on error patterns."""
    frameworks = []
    
    # Check for Express
    if "express" in response_text.lower() or (isinstance(error_data, dict) and any("express" in str(v).lower() for v in error_data.values())):
        frameworks.append("Express")
    
    # Check for Koa
    if "koa" in response_text.lower() or (isinstance(error_data, dict) and any("koa" in str(v).lower() for v in error_data.values())):
        frameworks.append("Koa")
    
    # Check for Hapi
    if "hapi" in response_text.lower() or "boom" in response_text.lower() or (isinstance(error_data, dict) and any(k in ("statusCode", "error", "message") for k in error_data)):
        frameworks.append("Hapi")
    
    # Check for NestJS
    if "nest" in response_text.lower() or (isinstance(error_data, dict) and any("nest" in str(v).lower() for v in error_data.values())):
        frameworks.append("NestJS")
    
    # Check for Fastify
    if "fastify" in response_text.lower() or (isinstance(error_data, dict) and any("fastify" in str(v).lower() for v in error_data.values())):
        frameworks.append("Fastify")
    
    return ", ".join(frameworks) if frameworks else "Unknown/Raw Node.js"


def extract_nodejs_version_hint(response_text: str, error_data: Dict) -> Optional[str]:
    """Extract Node.js version information if available in the error."""
    # Look for Node.js version in response
    version_match = re.search(r'node[:/\\]v?(\d+\.\d+\.\d+)', response_text, re.IGNORECASE)
    if version_match:
        return version_match.group(1)
    
    # Check if error data contains version
    if isinstance(error_data, dict) and error_data.get("versions") and error_data.get("versions").get("node"):
        return error_data.get("versions").get("node")
    
    return None


def determine_severity(error_type: str, status_code: int) -> str:
    """Determine the severity of an error based on type and status code."""
    # High severity errors
    high_severity_patterns = [
        "InternalServerError", "MemoryError", "DiskError", "UnhandledRejection",
        "UncaughtException", "DatabaseError", "ConnectionError", "CrashError"
    ]
    
    # Medium severity errors
    medium_severity_patterns = [
        "NotFoundError", "ValidationError", "AuthenticationError", "AuthorizationError",
        "TimeoutError", "RateLimitError", "ConfigurationError"
    ]
    
    # Determine by error type
    for pattern in high_severity_patterns:
        if pattern in error_type:
            return "HIGH"
    
    for pattern in medium_severity_patterns:
        if pattern in error_type:
            return "MEDIUM"
    
    # Determine by status code
    if status_code >= 500:
        return "HIGH"
    elif status_code >= 400:
        return "MEDIUM"
    
    return "LOW"


def get_nodejs_error_guidance(error_type: str, error_message: str, status_code: int) -> Tuple[List[str], List[str]]:
    """Get Node.js specific error guidance with potential causes and suggested fixes."""
    # Define common error types and their guidance
    error_guidance = {
        "TypeError": {
            "causes": [
                "Calling a method on an undefined or null value",
                "Passing a value of the wrong type to a function",
                "Trying to access a property of an undefined value",
                "Using an operator on incompatible types"
            ],
            "fixes": [
                "Check if variables are defined before using them",
                "Use typeof or optional chaining (?.) to safely access properties",
                "Validate function parameters before using them",
                "Ensure async functions properly await results"
            ]
        },
        "ReferenceError": {
            "causes": [
                "Using a variable that has not been declared",
                "Accessing a variable outside its scope",
                "Typo in variable or function name",
                "Using a variable before its declaration (temporal dead zone with let/const)"
            ],
            "fixes": [
                "Declare variables before using them",
                "Check for typos in variable or function names",
                "Use the correct scope when accessing variables",
                "Move variable declarations to the top of their scope"
            ]
        },
        "SyntaxError": {
            "causes": [
                "Missing bracket, parenthesis, or semicolon",
                "Invalid JavaScript/TypeScript syntax",
                "Using reserved keywords improperly",
                "Improper use of template literals or JSON formatting"
            ],
            "fixes": [
                "Use a linter to catch syntax errors",
                "Check for missing closing brackets or parentheses",
                "Validate JSON data before parsing",
                "Ensure proper use of async/await syntax"
            ]
        },
        "RangeError": {
            "causes": [
                "Array length or offset is invalid",
                "Numeric value is outside allowed range",
                "Call stack size exceeded (recursive function without proper termination)",
                "Invalid string length in operations"
            ],
            "fixes": [
                "Check array indexes before accessing them",
                "Add proper termination conditions to recursive functions",
                "Validate numeric inputs to be within expected ranges",
                "Consider using iterative approaches instead of recursion for large datasets"
            ]
        },
        "URIError": {
            "causes": [
                "Invalid characters in URI encoding/decoding functions",
                "Malformed URI in request handling",
                "Improper encoding of URL parameters"
            ],
            "fixes": [
                "Properly encode URI components before sending requests",
                "Validate and sanitize URL parameters",
                "Handle special characters in URLs correctly"
            ]
        },
        "InternalServerError": {
            "causes": [
                "Unhandled exception in request handler",
                "Database query failure",
                "Resource constraint exceeded (memory/CPU)",
                "Third-party service failure",
                "Synchronous code blocking the event loop"
            ],
            "fixes": [
                "Add proper error handling with try/catch blocks",
                "Implement global error handlers for Express/Koa/etc.",
                "Use PM2 or similar tools for process management",
                "Implement circuit breakers for external service calls",
                "Check server logs for detailed error information",
                "Ensure promises have error handling with .catch() or try/await/catch",
                "Move CPU-intensive operations to worker threads"
            ]
        },
        "NotFoundError": {
            "causes": [
                "Resource has been deleted or moved",
                "Route is not defined in the application",
                "Database record doesn't exist",
                "API endpoint misspelled or changed",
                "Path parameter is incorrect"
            ],
            "fixes": [
                "Verify the resource URL is correct",
                "Check if route handlers are properly defined",
                "Implement proper 404 handling middleware",
                "Validate database queries to ensure records exist",
                "Check for typos in resource identifiers"
            ]
        },
        "AuthenticationError": {
            "causes": [
                "Invalid or expired JWT token",
                "Missing authentication headers",
                "Incorrect user credentials",
                "Token signature verification failure",
                "Authentication service unavailable"
            ],
            "fixes": [
                "Refresh authentication token",
                "Check token expiration and format",
                "Verify credentials are being sent correctly",
                "Ensure auth middleware is configured properly",
                "Check if authentication service is available"
            ]
        },
        "AuthorizationError": {
            "causes": [
                "User lacks required permissions",
                "Access token does not contain necessary scopes",
                "Role-based access control misconfiguration",
                "IP restriction or geo-blocking",
                "Rate limiting or subscription limitations"
            ],
            "fixes": [
                "Verify user has the required permissions",
                "Check if token contains necessary scopes/claims",
                "Review RBAC configuration",
                "Check IP allowlists or geo-restrictions",
                "Verify account status and subscription level"
            ]
        },
        "ValidationError": {
            "causes": [
                "Required field is missing in the request body",
                "Field value doesn't match expected format or type",
                "Input data exceeds maximum length",
                "Schema validation failure",
                "Malformed JSON in request body"
            ],
            "fixes": [
                "Validate request payload against expected schema",
                "Check for missing required fields",
                "Ensure data formats match expected patterns",
                "Implement proper input validation middleware",
                "Format JSON data correctly"
            ]
        },
        "ConnectionError": {
            "causes": [
                "Database connection failed or timed out",
                "Network connectivity issues",
                "Third-party API is unreachable",
                "Firewall blocking connection",
                "Incorrect connection string or credentials"
            ],
            "fixes": [
                "Verify network connectivity",
                "Check database/service credentials",
                "Implement connection pooling",
                "Add retry logic with exponential backoff",
                "Verify firewall and security group settings"
            ]
        },
        "DatabaseError": {
            "causes": [
                "Query syntax error",
                "Database constraint violation",
                "Deadlock in transaction",
                "Connection pool exhausted",
                "Missing indexes causing performance issues"
            ],
            "fixes": [
                "Validate SQL/NoSQL query syntax",
                "Handle database constraint errors gracefully",
                "Implement proper transaction management",
                "Optimize queries with indexes",
                "Use parameterized queries to prevent injection",
                "Consider implementing database migrations"
            ]
        },
        "TimeoutError": {
            "causes": [
                "Long-running operation exceeded timeout",
                "External API call took too long",
                "Database query timeout",
                "Network latency",
                "Request handler stuck in infinite loop"
            ],
            "fixes": [
                "Implement timeouts for all external calls",
                "Optimize database queries and add indexes",
                "Consider using asynchronous processing for long operations",
                "Split large operations into smaller chunks",
                "Add circuit breakers for external dependencies"
            ]
        },
        "MemoryError": {
            "causes": [
                "Memory leak in application code",
                "Large dataset processing without streaming",
                "Too many concurrent connections",
                "Inefficient object creation and garbage collection",
                "Node.js heap size limit reached"
            ],
            "fixes": [
                "Use streams for large data processing",
                "Monitor memory usage with tools like clinic.js",
                "Implement pagination for large datasets",
                "Increase Node.js memory limit if necessary: --max-old-space-size",
                "Check for unresolved promises or event listeners"
            ]
        },
        "RateLimitError": {
            "causes": [
                "Too many requests to an API",
                "Missing or invalid API key",
                "Quota exceeded for service",
                "IP-based rate limiting",
                "Distributed denial of service detection"
            ],
            "fixes": [
                "Implement request throttling",
                "Add exponential backoff for retries",
                "Check API quota and usage limits",
                "Use API key rotation strategy",
                "Implement caching to reduce API calls"
            ]
        },
        "ExpressRouteError": {
            "causes": [
                "Route not defined in Express application",
                "Route pattern mismatch",
                "Wrong HTTP method used for endpoint",
                "Middleware terminating request chain",
                "Router mounted at wrong path"
            ],
            "fixes": [
                "Check route definitions in Express app",
                "Verify HTTP methods (GET, POST, etc.) match endpoints",
                "Ensure middleware calls next() when appropriate",
                "Check router mounting paths",
                "Add fallback 404 handler"
            ]
        },
        "JsonWebTokenError": {
            "causes": [
                "Expired JWT token",
                "Invalid token signature",
                "Token payload tampered with",
                "Wrong algorithm used for verification",
                "Missing required claims"
            ],
            "fixes": [
                "Check token expiration (exp claim)",
                "Verify token was signed with correct secret",
                "Validate required claims like iss, sub, aud",
                "Ensure correct algorithm is used for verification",
                "Implement proper token refresh mechanism"
            ]
        },
        "ConfigurationError": {
            "causes": [
                "Missing environment variables",
                "Invalid configuration format",
                "Conflicting configuration values",
                "Wrong environment-specific settings",
                "Configuration file not found or inaccessible"
            ],
            "fixes": [
                "Validate all required environment variables on startup",
                "Use environment variable validation libraries",
                "Implement proper configuration schema validation",
                "Use dotenv for local development",
                "Add clear error messages for missing configuration"
            ]
        }
    }
    
    # Default error guidance
    default_guidance = {
        "causes": [
            "Unknown server-side error",
            "Unhandled exception in application code",
            "External dependency failure"
        ],
        "fixes": [
            "Check server logs for detailed error information",
            "Implement proper error handling",
            "Review recent code changes",
            "Check external service status"
        ]
    }
    
    # Get guidance based on error type, with fallback to status code based guidance
    guidance = error_guidance.get(error_type)
    
    # If no specific guidance for the error type, try to find based on partial match
    if not guidance:
        for err_type, guide in error_guidance.items():
            if err_type in error_type:
                guidance = guide
                break
    
    # If still no guidance, use HTTP status code based guidance
    if not guidance and status_code >= 400:
        status_guidance = {
            400: error_guidance.get("ValidationError"),
            401: error_guidance.get("AuthenticationError"),
            403: error_guidance.get("AuthorizationError"),
            404: error_guidance.get("NotFoundError"),
            408: error_guidance.get("TimeoutError"),
            429: error_guidance.get("RateLimitError"),
            500: error_guidance.get("InternalServerError"),
            502: {
                "causes": [
                    "Proxy or gateway error",
                    "Upstream server unavailable or returning invalid response",
                    "Load balancer issue"
                ],
                "fixes": [
                    "Check if upstream services are functioning correctly",
                    "Verify proxy or API gateway configuration",
                    "Check load balancer health checks",
                    "Implement circuit breakers for upstream services"
                ]
            },
            503: {
                "causes": [
                    "Service temporarily unavailable",
                    "Server is under maintenance",
                    "Server is overloaded",
                    "Required service dependencies are down"
                ],
                "fixes": [
                    "Implement auto-scaling for high traffic periods",
                    "Check service dependencies status",
                    "Add rate limiting to prevent overload",
                    "Implement proper maintenance mode handling"
                ]
            },
            504: error_guidance.get("TimeoutError")
        }
        
        guidance = status_guidance.get(status_code)
    
    # If still no guidance, use default
    if not guidance:
        guidance = default_guidance
    
    # Customize guidance based on specific error message patterns
    if "ECONNREFUSED" in error_message:
        guidance["causes"].append("Connection refused - service may not be running")
        guidance["fixes"].append("Check if the target service is running and accepting connections")
    
    if "ENOTFOUND" in error_message:
        guidance["causes"].append("Domain name resolution failed")
        guidance["fixes"].append("Verify domain name is correct and DNS is properly configured")
    
    if "heap" in error_message.lower() or "memory" in error_message.lower():
        if "MemoryError" not in error_type:
            guidance["causes"].extend(error_guidance.get("MemoryError", {}).get("causes", []))
            guidance["fixes"].extend(error_guidance.get("MemoryError", {}).get("fixes", []))
    
    return guidance["causes"], guidance["fixes"]


def create_error_detail(exception: Exception) -> ApiErrorDetail:
    """Create error detail object from a Python exception."""
    error_type = type(exception).__name__
    error_message = str(exception)
    
    # Determine potential causes and fixes based on exception type
    if isinstance(exception, (ConnectionError, socket.error)):
        potential_causes = [
            "Network connectivity issue",
            "Service is down or unreachable",
            "Firewall blocking connection"
        ]
        suggested_fixes = [
            "Check network connectivity",
            "Verify service is running",
            "Check firewall settings"
        ]
        severity = "HIGH"
    elif isinstance(exception, TimeoutError):
        potential_causes = [
            "Request took too long to complete",
            "Service is overloaded",
            "Network latency issues"
        ]
        suggested_fixes = [
            "Increase timeout value",
            "Retry with exponential backoff",
            "Check service load"
        ]
        severity = "MEDIUM"
    elif isinstance(exception, json.JSONDecodeError):
        potential_causes = [
            "Response is not valid JSON",
            "Partial response received",
            "Content-Type mismatch"
        ]
        suggested_fixes = [
            "Check response format",
            "Verify content type headers",
            "Implement error handling for non-JSON responses"
        ]
        severity = "MEDIUM"
    else:
        potential_causes = ["Unexpected error during request processing"]
        suggested_fixes = ["Check exception details and implement specific handling"]
        severity = "HIGH"
    
    return ApiErrorDetail(
        error_type=error_type,
        error_message=error_message,
        stack_trace=None,
        line_number=None,
        code_snippet=None,
        potential_causes=potential_causes,
        suggested_fixes=suggested_fixes,
        severity=severity,
        timestamp=datetime.now().isoformat(),
        additional_context={
            "exception_type": error_type,
            "exception_args": [str(arg) for arg in exception.args]
        }
    )

import time  

def check_ssl_security(cert: Dict) -> List[Dict]:
    """Check SSL certificate for security issues."""
    issues = []
    
    # Check certificate expiration
    if 'notAfter' in cert:
        expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
        current_time = time.time()
        days_left = (expiry_date - current_time) / (24 * 3600)
        
        if days_left < 0:
            issues.append({
                "type": "SSL_CERTIFICATE_EXPIRED",
                "severity": "HIGH",
                "description": f"SSL certificate has expired on {cert['notAfter']}",
                "recommendation": "Renew SSL certificate immediately"
            })
        elif days_left < 30:
            issues.append({
                "type": "SSL_CERTIFICATE_EXPIRING_SOON",
                "severity": "MEDIUM",
                "description": f"SSL certificate expires in {days_left:.1f} days",
                "recommendation": "Renew SSL certificate before expiration"
            })
    
    # Check for weak cipher suites (mock check, as we can't directly test from here)
    issues.append({
        "type": "SSL_CONFIGURATION_CHECK",
        "severity": "INFO",
        "description": "Consider checking for weak cipher suites and protocols",
        "recommendation": "Use tools like SSL Labs or testssl.sh for complete TLS/SSL security audit"
    })
    
    return issues


async def analyze_internal_server_error(api_url: str) -> List[ApiErrorDetail]:
    """Perform deeper analysis of 500 Internal Server Errors."""
    errors = []
    
    # Add common Node.js 500 error guidance
    internal_error = ApiErrorDetail(
        error_type="InternalServerErrorAnalysis",
        error_message="Detailed analysis of Internal Server Error",
        stack_trace=None,
        line_number=None,
        code_snippet=None,
        potential_causes=[
            "Unhandled promise rejection",
            "Uncaught exception in async code",
            "Database connection failure",
            "Memory leak or resource exhaustion",
            "Improper error handling in middleware",
            "Malformed request handling",
            "Third-party module failure"
        ],
        suggested_fixes=[
            "Implement global unhandled rejection handler: process.on('unhandledRejection', handler)",
            "Add try/catch blocks around async code or use .catch() with promises",
            "Implement global error middleware in Express/Koa",
            "Check for memory leaks using tools like clinic.js",
            "Validate input data before processing",
            "Implement robust logging (Winston, Bunyan, Pino)",
            "Use PM2 or similar process manager for automatic restarts"
        ],
        severity="HIGH",
        timestamp=datetime.now().isoformat(),
        additional_context={
            "nodejs_specific": True,
            "common_frameworks": "Express, Koa, Hapi, NestJS, Fastify"
        }
    )
    
    errors.append(internal_error)
    return errors


def generate_recommendations(analysis_result: Dict) -> List[str]:
    """Generate actionable recommendations based on API analysis."""
    recommendations = []
    
    # Error handling recommendations
    if any(error.error_type == "InternalServerError" for error in analysis_result.get("errors", [])):
        recommendations.extend([
            "Implement centralized error handling middleware for all routes",
            "Add detailed logging with context for server errors",
            "Consider using a process manager like PM2 for automatic restarts",
            "Implement health check endpoints to monitor service status"
        ])
    
    # Performance recommendations
    response_time = analysis_result.get("performance_metrics", {}).get("response_time", 0)
    if response_time > 1.0:
        recommendations.extend([
            f"Response time ({response_time:.2f}s) is high, consider optimization",
            "Profile Node.js application to identify bottlenecks",
            "Consider implementing caching for frequently accessed data",
            "Check database query performance and add indexes where needed"
        ])
    
    # Security recommendations
    if analysis_result.get("security_issues"):
        recommendations.extend([
            "Address identified security issues with SSL/TLS configuration",
            "Implement proper CORS policy and security headers",
            "Use Helmet.js to set security-related HTTP headers",
            "Regularly update Node.js and npm dependencies to fix vulnerabilities"
        ])
    
    # Status code specific recommendations
    if analysis_result.get("status_code") == 404:
        recommendations.append("Implement proper 404 handling and user-friendly error pages")
    elif analysis_result.get("status_code") == 429:
        recommendations.append("Implement client-side rate limiting and backoff strategies")
    
    # Add Node.js specific recommendations
    recommendations.extend([
        "Use async/await pattern with proper error handling for asynchronous code",
        "Implement structured logging with request IDs for traceability",
        "Consider using TypeScript for improved type safety and developer experience"
    ])
    
    return recommendations

async def deep_api_analysis(api_url: str, method: str = "GET", payload: Optional[Dict] = None) -> ApiAnalysisResult:
    """
    Performs comprehensive API analysis for Node.js applications including error detection,
    security checks, performance metrics, and generates detailed recommendations.
    
    Args:
        api_url: The API endpoint URL (can be full URL or local endpoint like "api/error")
        method: HTTP method (GET, POST, PUT, DELETE, etc.), defaults to GET
        payload: Optional request payload for POST/PUT requests
    """
    
    start_time = datetime.now()
    analysis_result = {
        "endpoint": api_url,
        "status_code": 0,
        "response_time": 0,
        "errors": [],
        "security_issues": [],
        "performance_metrics": {},
        "recommendations": []
    }
    
    try:
        # Parse URL for basic validation and handle local endpoints
        parsed_url = urlparse(api_url)
        if not parsed_url.scheme:  # Handle endpoints like "api/error"
            api_url = f"http://localhost:3000/{api_url.lstrip('/')}"  # Default local setup
            parsed_url = urlparse(api_url)
        
        if not parsed_url.netloc:
            raise ValueError(f"Invalid URL format: {api_url}")
        
        # Determine if URL is localhost or internal
        hostname = parsed_url.hostname
        is_local = hostname in ("localhost", "127.0.0.1") or (hostname and hostname.startswith("192.168."))
        
        # Basic connection test for non-local URLs
        if not is_local:
            try:
                # Determine port to use
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                sock = socket.create_connection((parsed_url.hostname, port), timeout=10)
                
                # Security check - SSL/TLS for HTTPS
                if parsed_url.scheme == 'https':
                    try:
                        import ssl
                        context = ssl.create_default_context()
                        with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                            cert = ssock.getpeercert()
                            analysis_result["security_issues"].extend(check_ssl_security(cert))
                    except Exception as e:
                        analysis_result["security_issues"].append({
                            "type": "SSL_CONNECTION_ERROR",
                            "severity": "HIGH",
                            "description": f"Failed to establish SSL connection: {str(e)}",
                            "recommendation": "Verify SSL configuration and certificate validity"
                        })
                    finally:
                        sock.close()
            except Exception as e:
                error_detail = create_error_detail(e)
                analysis_result["errors"].append(error_detail)
        
        # Perform HTTP request with detailed metrics
        timeout = aiohttp.ClientTimeout(total=150)
        headers = {
            "User-Agent": "NodeJS-API-Analyzer/1.0",
            "Accept": "application/json, text/plain, */*"
        }
        
        # Custom timeout for connection and response
        connection_start = datetime.now()
        connection_time = None
        ttfb = None  # Time To First Byte
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                # Send request with detailed timing based on method
                method = method.upper()
                response = None
                if method == "GET":
                    response = await session.get(api_url, headers=headers, allow_redirects=True)
                elif method == "POST":
                    response = await session.post(api_url, headers=headers, json=payload or {})
                elif method == "PUT":
                    response = await session.put(api_url, headers=headers, json=payload or {})
                elif method == "DELETE":
                    response = await session.delete(api_url, headers=headers)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                async with response:
                    connection_time = (datetime.now() - connection_start).total_seconds()
                    
                    # Capture TTFB by reading first byte
                    first_chunk = await response.content.read(1)
                    ttfb = (datetime.now() - connection_start).total_seconds()
                    
                    # Continue reading the response
                    response_data = first_chunk + await response.read()
                    response_text = response_data.decode("utf-8", errors="replace")
                    
                    # Record status code and response details
                    analysis_result["status_code"] = response.status
                    
                    # Get response headers
                    response_headers = dict(response.headers)
                    
                    # Check for common Node.js framework headers
                    framework_headers = detect_nodejs_framework_from_headers(response_headers)
                    
                    # Check for security headers
                    security_headers_issues = check_security_headers(response_headers)
                    analysis_result["security_issues"].extend(security_headers_issues)
                    
                    # Analyze response if it's an error
                    if response.status >= 400:
                        error_detail = await analyze_error_response(response_text, response.status)
                        analysis_result["errors"].append(error_detail)
                        
                        # For 500 errors, do deeper analysis
                        if response.status == 500:
                            analysis_result["errors"].extend(await analyze_internal_server_error(api_url))
                    
                    # Performance metrics
                    response_time = (datetime.now() - start_time).total_seconds()
                    analysis_result["performance_metrics"] = {
                        "response_time": response_time,
                        "connection_time": connection_time,
                        "time_to_first_byte": ttfb,
                        "response_size": len(response_data),
                        "headers": response_headers,
                        "detected_framework": framework_headers,
                        "method_used": method  # Added to track which method was used
                    }
                    
            except asyncio.TimeoutError:
                error_detail = ApiErrorDetail(
                    error_type="RequestTimeoutError",
                    error_message="Request timed out after 30 seconds",
                    stack_trace=None,
                    line_number=None,
                    code_snippet=None,
                    potential_causes=[
                        "Server is taking too long to process the request",
                        "Network latency issues",
                        "Server is overloaded",
                        "Endpoint involves heavy processing without proper optimizations",
                        "Node.js event loop is blocked by synchronous operations"
                    ],
                    suggested_fixes=[
                        "Increase client timeout threshold",
                        "Optimize server-side processing",
                        "Implement async processing for heavy operations",
                        "Use worker threads for CPU-intensive tasks",
                        "Check for event loop blocking operations",
                        "Consider implementing streaming responses for large data"
                    ],
                    severity="HIGH",
                    timestamp=datetime.now().isoformat(),
                    additional_context={
                        "timeout_threshold": "30 seconds",
                        "nodejs_specific": "Event loop may be blocked"
                    }
                )
                analysis_result["errors"].append(error_detail)
                analysis_result["status_code"] = 408  # Request Timeout
                
            except Exception as e:
                error_detail = create_error_detail(e)
                analysis_result["errors"].append(error_detail)
                
    except Exception as e:
        error_detail = create_error_detail(e)
        analysis_result["errors"].append(error_detail)
    
    # Generate final recommendations
    analysis_result["recommendations"] = generate_recommendations(analysis_result)
    analysis_result["response_time"] = (datetime.now() - start_time).total_seconds()
    
    return ApiAnalysisResult(**analysis_result)

def detect_nodejs_framework_from_headers(headers: Dict) -> str:
    """Detect Node.js framework from response headers."""
    framework_indicators = {
        "Express": ["x-powered-by", "Express"],
        "Koa": ["koa", "powered-by-koa"],
        "NestJS": ["x-powered-by", "nestjs"],
        "Fastify": ["x-powered-by", "fastify"],
        "Hapi": ["hapi"],
        "Next.js": ["next-head-count"],
        "Nuxt.js": ["nuxt"],
        "Strapi": ["x-strapi"],
        "LoopBack": ["x-powered-by", "loopback"],
        "Sails.js": ["x-powered-by", "sails"]
    }
    
    detected = []
    
    # Check for known framework headers
    for framework, indicators in framework_indicators.items():
        if len(indicators) == 1:
            # Single indicator just needs to be present as a key
            if indicators[0].lower() in [h.lower() for h in headers.keys()]:
                detected.append(framework)
        elif len(indicators) == 2:
            # Key-value pair needs to match
            header_key = indicators[0].lower()
            header_value = indicators[1].lower()
            if header_key in [h.lower() for h in headers.keys()]:
                for key, value in headers.items():
                    if key.lower() == header_key and header_value in value.lower():
                        detected.append(framework)
    
    # Check for Node.js specific patterns
    if "x-powered-by" in headers and "nodejs" in headers["x-powered-by"].lower():
        detected.append("Node.js")
    
    # Check for generic web server headers
    server_header = headers.get("server", "").lower()
    if "node" in server_header:
        detected.append("Node.js")
    
    return ", ".join(detected) if detected else "Unknown"


def check_security_headers(headers: Dict) -> List[Dict]:
    """Check for missing or misconfigured security headers in Node.js application."""
    security_issues = []
    
    # Essential security headers
    security_headers = {
        "strict-transport-security": {
            "description": "HTTP Strict Transport Security (HSTS)",
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
        },
        "content-security-policy": {
            "description": "Content Security Policy (CSP)",
            "recommendation": "Implement a strict CSP header to prevent XSS attacks"
        },
        "x-content-type-options": {
            "description": "X-Content-Type-Options",
            "recommendation": "Add 'X-Content-Type-Options: nosniff' header"
        },
        "x-frame-options": {
            "description": "X-Frame-Options",
            "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header"
        },
        "x-xss-protection": {
            "description": "X-XSS-Protection",
            "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header"
        }
    }
    
    # Check for missing headers
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for header, info in security_headers.items():
        if header not in headers_lower:
            security_issues.append({
                "type": f"MISSING_SECURITY_HEADER_{header.upper().replace('-', '_')}",
                "severity": "MEDIUM",
                "description": f"Missing {info['description']} header",
                "recommendation": info["recommendation"]
            })
    
    # Check for specific Node.js header leaks
    if "x-powered-by" in headers_lower:
        security_issues.append({
            "type": "INFORMATION_DISCLOSURE",
            "severity": "LOW",
            "description": "X-Powered-By header reveals technology stack information",
            "recommendation": "Remove X-Powered-By header using Helmet.js or custom middleware"
        })
    
    return security_issues







async def get_file_content(url: str, headers: dict) -> tuple[str, str]:
    """Get file content and detect its type."""
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        # Get the raw content
        raw_content = response.content
        
        # Detect mime type
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(raw_content)
        
        # Handle different file types
        if 'text' in file_type or file_type in ['application/json', 'application/javascript', 'application/xml']:
            # Text files - decode and return as is
            try:
                content = raw_content.decode('utf-8')
            except UnicodeDecodeError:
                content = raw_content.decode('latin-1')
        else:
            # Binary files - base64 encode
            content = base64.b64encode(raw_content).decode('utf-8')
            
        return content, file_type
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching file content: {str(e)}")


def find_apis_in_content(content: str) -> List[str]:
    """Find API endpoints in file content using regex patterns."""
    apis_found = []
    for pattern in API_PATTERNS:
        matches = re.finditer(pattern, content)
        apis_found.extend([match.group() for match in matches])
    return list(set(apis_found))  # Remove duplicates

async def scan_file_content(content: str, file_path: str) -> dict:
    """Scan file content for APIs and analyze them."""
    apis = find_apis_in_content(content)
    results = {
        "apis_found": [],
        "errors_detected": [],
        "solutions": []
    }
    
    for api in apis:
        try:
            # Check each API found
            check_result = await check_api(api)
            results["apis_found"].append(api)
            
            if check_result.error:
                results["errors_detected"].append({
                    "api": api,
                    "error": check_result.error
                })
                results["solutions"].append({
                    "api": api,
                    "solution": check_result.solution,
                    "auto_fix_available": bool(check_result.solution)
                })
        except Exception as e:
            print(f"Error scanning API {api}: {str(e)}")
            
    return results


@app.get("/api/repos/{owner}/{repo}/contents/{path:path}", response_model=List[RepoContent])
async def get_repo_contents(
    request: Request,
    owner: str,
    repo: str,
    path: str = ""
    
):
    """Get contents of a repository with optional path."""
    # Get token from Authorization header or session
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        token = request.session.get("github_token")
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        contents = response.json()
        
        if not isinstance(contents, list):
            contents = [contents]
            
        result = []
        for item in contents:
            content_item = RepoContent(
                name=item["name"],
                path=item["path"],
                type=item["type"],
                sha=item["sha"],
                size=item.get("size")
            )
            
            if item["type"] == "file":
                # Get file content for files
                file_response = requests.get(item["download_url"], headers=headers)
                if file_response.ok:
                    file_content = file_response.text
                    apis_found = find_apis_in_content(file_content)
                    content_item.content = [{
                        "name": item["name"],
                        "path": item["path"],
                        "sha": item["sha"],
                        "size": item["size"],
                        "url": item["download_url"],
                        "content": file_content,
                        "type": "file",
                        "apis_found": apis_found
                    }]
            
            result.append(content_item)
            
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@app.post("/scan-file")
async def scan_file(
    request: Request,
    file_data: dict
):
    """Scan a file or API URL for potential issues."""
    try:
        # Get token from header or session
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            token = request.session.get("github_token")
            if not token:
                raise HTTPException(status_code=401, detail="Not authenticated")

        api_url = file_data.get("api_url")
        if api_url:
            # For direct API URL scanning
            apis_found = [api_url]
            scan_results = {
                "apis_found": apis_found,
                "errors_detected": [],
                "solutions": []
            }

            # Check API health
            try:
                response = requests.get(api_url, timeout=10)
                if response.status_code >= 400:
                    scan_results["errors_detected"].append({
                        "error": f"API returned error status: {response.status_code}"
                    })
                    scan_results["solutions"].append({
                        "solution": ai_model_suggest_fix(f"API error {response.status_code}")
                    })
            except requests.exceptions.RequestException as e:
                scan_results["errors_detected"].append({
                    "error": f"API connection error: {str(e)}"
                })
                scan_results["solutions"].append({
                    "solution": ai_model_suggest_fix(str(e))
                })

            return {
                "type": "api_check",
                "content": api_url,
                "content_type": "text/plain",
                "scan_results": scan_results
            }
        else:
            # For file scanning (existing logic)
            owner = file_data.get("owner")
            repo = file_data.get("repo")
            path = file_data.get("path")
            
            if not all([owner, repo, path]):
                raise HTTPException(status_code=422, detail="Missing required fields")

            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            file_data = response.json()

            content, file_type = await get_file_content(file_data["download_url"], headers)
            scan_results = await scan_file_content(content, path)

            return {
                "file_path": path,
                "type": file_data["type"],
                "content": content,
                "content_type": file_type,
                "scan_results": scan_results
            }

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"GitHub API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")
    

# @app.post("/apply-fix")
# async def apply_fix(
#     request: Request,
#     fix_data: FixRequest
# ):
#     """Modified endpoint to create GitHub issues with suggested fixes."""
#     try:
#         # Extract token from Authorization header
#         auth_header = request.headers.get("Authorization")
#         if not auth_header or not auth_header.startswith("Bearer "):
#             raise HTTPException(
#                 status_code=401,
#                 detail="Missing or invalid Authorization header"
#             )
        
#         token = auth_header.replace("Bearer ", "")
        
#         # Validate the token with GitHub
#         try:
#             headers = {
#                 "Authorization": f"token {token}",
#                 "Accept": "application/json"
#             }
#             github_response = requests.get("https://api.github.com/user", headers=headers)
            
#             if github_response.status_code != 200:
#                 # Return more detailed error message for debugging
#                 error_detail = {
#                     "status_code": github_response.status_code,
#                     "message": "GitHub token is invalid or expired. Please log in again.",
#                     "github_response": github_response.text[:200]  # First 200 chars for debugging
#                 }
#                 raise HTTPException(
#                     status_code=401,
#                     detail=json.dumps(error_detail)
#                 )
#         except requests.RequestException as token_error:
#             print(f"Token validation error: {str(token_error)}")
#             raise HTTPException(
#                 status_code=401,
#                 detail=f"Failed to validate GitHub token: {str(token_error)}"
#             )
        
#         # Generate solution using DeepSeek API
#         solution = await generate_solution_with_deepseek(fix_data.api_url, fix_data.fix_content)
        
#         # Return the solution and token
#         return {
#             "status": "success",
#             "message": "Ready to create GitHub issue",
#             "solution": solution,
#             "github_token": token
#         }
        
#     except HTTPException as he:
#         # Pass through HTTP exceptions
#         raise he
#     except Exception as e:
#         print(f"Error in apply_fix: {str(e)}")
#         import traceback
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))

# async def generate_solution_with_deepseek(api_url: str, error_content: str):
#     """Generate a solution using DeepSeek API."""
#     try:
#         import os
#         import requests
        
#         deepseek_api_key = os.getenv("DEEPSEEK_API")
#         if not deepseek_api_key:
#             raise ValueError("DeepSeek API key not found in environment variables")
        
#         # Prepare prompt for DeepSeek
#         prompt = f"""
#         I need to fix an issue with the following Node.js API endpoint: {api_url}
        
#         The error is:
#         {error_content}
        
#         Please provide a detailed solution with code snippets that I can implement to fix this issue.
#         """
        
#         # Make request to DeepSeek API
#         response = requests.post(
#             "https://api.deepseek.com/v1/chat/completions",
#             headers={
#                 "Authorization": f"Bearer {deepseek_api_key}",
#                 "Content-Type": "application/json"
#             },
#             json={
#                 "model": "deepseek-coder",
#                 "messages": [{"role": "user", "content": prompt}],
#                 "temperature": 0.7,
#                 "max_tokens": 1500
#             }
#         )
        
#         if response.status_code != 200:
#             raise ValueError(f"DeepSeek API error: {response.text}")
        
#         result = response.json()
#         return result["choices"][0]["message"]["content"]
    
#     except Exception as e:
#         print(f"Error generating solution: {str(e)}")
#         return f"Unable to generate solution. Error: {str(e)}"
    
    
# Load AI Model on startup
@app.on_event("startup")
async def startup_event():
    global model, tokenizer
    try:
        print("Loading model from:", MODEL_PATH)
        if not os.path.exists(MODEL_PATH):
            print(f"Warning: Model path {MODEL_PATH} does not exist. Creating directory...")
            os.makedirs(MODEL_PATH, exist_ok=True)
            print("Please ensure you have copied your model files to the model_output directory")
            return

        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        print("Model loaded successfully!")
    except Exception as e:
        print(f"Warning: Error loading model: {e}")
        print("The API will start but AI features will be limited")

# Helper Functions
def detect_hosting_platform(api_url: str) -> str:
    platform_patterns = {
        "localhost": "Local Development",
        "github.io": "GitHub Pages",
        "vercel.app": "Vercel",
        "firebaseapp.com": "Firebase",
        "herokuapp.com": "Heroku",
        "cloudfunctions.net": "Google Cloud",
        "aws.amazon.com": "AWS",
        "azure.com": "Azure",
        "netlify.app": "Netlify"
    }
    
    for pattern, platform in platform_patterns.items():
        if pattern in api_url.lower():
            return platform
    return "Custom/Unknown Platform"

def ai_model_suggest_fix(error_text: str) -> str:
    if not model or not tokenizer:
        return "AI model not loaded yet. Using fallback suggestions."
    
    try:
        inputs = tokenizer(error_text, return_tensors="pt", padding=True, truncation=True)
        with torch.no_grad():
            outputs = model(**inputs)
        predicted_fix = torch.argmax(outputs.logits, dim=-1).item()
        return f"AI Suggested Fix: {predicted_fix}"
    except Exception as e:
        return f"Error generating AI fix: {str(e)}"

# Routes
@app.get("/")
async def root():
    model_status = "loaded" if model and tokenizer else "not loaded"
    return {
        "message": "Welcome to CloudPatch.ai API",
        "version": "1.0.0",
        "model_status": model_status
    }

@app.get("/login/github")
async def github_login():
    return {
        "url": f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=repo"
    }

# main.py updates

@app.get("/auth/github/callback")
async def github_callback(code: str, request: Request):
    try:
        # Exchange code for access token
        response = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code
            }
        )
        response.raise_for_status()
        token_data = response.json()
        
        if "access_token" not in token_data:
            raise HTTPException(status_code=400, detail="Failed to obtain access token")
            
        token = token_data["access_token"]
        
        # Store token in session
        request.session["github_token"] = token
        
        # Get user data
        user_response = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/json"
            }
        )
        user_data = user_response.json()
        
        # Get return path from query params or default to '/'
        return_to = request.query_params.get('return_to', '/')
        
        # Return both token and user data with return path
        return JSONResponse({
            "token": token,
            "user": {
                "id": user_data["id"],
                "login": user_data["login"],
                "avatar_url": user_data["avatar_url"]
            },
            "return_to": return_to
        })
        
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")



@app.get("/api/user/repos")
async def get_user_repos(request: Request):
    # Get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        # Fallback to session token
        token = request.session.get("github_token")
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")
    else:
        token = auth_header.split(" ")[1]
    
    try:
        response = requests.get(
            "https://api.github.com/user/repos",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }
        )
        response.raise_for_status()
        return response.json()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()  # Clear all session data
    return {"message": "Logged out successfully"}

import logging
from fastapi import Query, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional, Dict
from urllib.parse import urlparse
import aiohttp
import traceback
import asyncio
import socket

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.get("/check-api", response_model=ApiCheckResponse)
async def check_api(
    api_url: str = Query(..., description="URL of the API to check"),
    method: str = Query("GET", description="HTTP method to use"),
    port: Optional[int] = Query(None, description="Port for local endpoints"),
    request: Request = None
):
    """
    Check the status of an API endpoint, supporting both local and cloud-hosted APIs.
    Returns detailed error analysis and suggestions for fixes if issues are detected.
    Provides enhanced validation for local endpoints, port availability, and network connectivity.
    """
    try:
        # Log the incoming request for debugging
        logger.debug(f"Checking API: {api_url} with method {method} on port {port}")

        # Get token if available for authenticated requests
        token = request.headers.get("Authorization", "").replace("Bearer ", "") or request.session.get("github_token")

        # Enhanced URL parsing and local endpoint detection
        parsed_url = urlparse(api_url)
        
        # Define what we consider as local hostnames
        local_hostnames = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
        
        # Check if the URL is local based on hostname or lack of scheme
        is_local = parsed_url.hostname in local_hostnames or not parsed_url.scheme
        
        # Validate URL format more thoroughly
        if not parsed_url.scheme and not parsed_url.netloc and '.' in parsed_url.path and not any(lh in parsed_url.path for lh in local_hostnames):
            # This might be a case where user entered something like "api.example.com/endpoint" without http://
            return create_error_response(
                "Invalid URL format",
                f"The URL '{api_url}' appears to be missing a protocol (http:// or https://). Did you mean 'http://{api_url}'?",
                additional_info={
                    "error_type": "URL_FORMAT_ERROR",
                    "suggested_url": f"http://{api_url}",
                    "is_local": False
                }
            )
        
        if is_local:
            # Standardize the local URL format
            port = port or 3000  # Default to 3000 if not provided
            
            # Handle URLs without a scheme or with just a path
            if not parsed_url.scheme:
                # If it's just a path or relative URL
                if api_url.startswith('/'):
                    api_url = f"http://localhost:{port}{api_url}"
                else:
                    api_url = f"http://localhost:{port}/{api_url}"
            else:
                # If it has a scheme but we need to ensure the port is correct
                netloc = parsed_url.netloc.split(':')[0]  # Get hostname without port
                path = parsed_url.path
                query = f"?{parsed_url.query}" if parsed_url.query else ""
                api_url = f"http://{netloc}:{port}{path}{query}"
            
            parsed_url = urlparse(api_url)
            logger.debug(f"Constructed local URL: {api_url}")
            
            # Advanced port checking - check if the port is actually in use by any process
            try:
                # Create a socket to test if the port is in use by any process
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                
                if result != 0:
                    # Port is not in use by any process
                    return create_error_response(
                        "Service not running",
                        f"No service detected on port {port}. Please start your local server or check the port number.",
                        additional_info={
                            "error_type": "PORT_NOT_IN_USE",
                            "is_local": True,
                            "attempted_url": api_url,
                            "port": port,
                            "troubleshooting_steps": [
                                f"Start your server on port {port}",
                                "Check if you specified the correct port number",
                                f"Run 'netstat -an | grep {port}' to check if anything is listening on this port",
                                "Ensure no firewall is blocking access to this port"
                            ]
                        }
                    )
            except socket.error as e:
                logger.error(f"Socket error when checking port: {str(e)}")
            
            # For local endpoints, check if the API is reachable and correctly set up
            async with aiohttp.ClientSession() as session:
                try:
                    method = method.upper()
                    headers = {"User-Agent": "CloudPatch-Analyzer/1.0"}
                    if token:
                        headers["Authorization"] = f"Bearer {token}"

                    # First do a quick check to see if the server is running
                    try:
                        # Set a short timeout for the initial connection check
                        async with session.head(
                            f"http://localhost:{port}", 
                            timeout=aiohttp.ClientTimeout(total=2),
                            headers=headers
                        ) as head_response:
                            # Server is running but we still need to check the specific endpoint
                            logger.debug(f"Server on port {port} is responding with status {head_response.status}")
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        # Connection error means server isn't running
                        if "Connection refused" in str(e):
                            return create_error_response(
                                "Connection refused",
                                f"Connection to localhost:{port} was refused. Make sure your server is running on this port.",
                                additional_info={
                                    "error_type": "CONNECTION_REFUSED",
                                    "is_local": True,
                                    "attempted_url": api_url,
                                    "troubleshooting_steps": [
                                        f"Start your server on port {port}",
                                        "Check if your server logs show any startup errors",
                                        "Ensure no other application is using this port"
                                    ]
                                }
                            )
                        # Otherwise fall back to generic error
                        logger.error(f"Initial connectivity check failed: {str(e)}")
                        return create_error_response(
                            "Local server not responding",
                            f"Could not connect to localhost:{port}: {str(e)}. Please ensure your local server is running properly.",
                            additional_info={
                                "error_type": "CONNECTION_ERROR",
                                "is_local": True,
                                "attempted_url": api_url,
                                "error_details": str(e)
                            }
                        )

                    # Now try the specific endpoint with the requested method
                    try:
                        # Use a more reasonable timeout for the actual endpoint check
                        timeout = aiohttp.ClientTimeout(total=10)
                        
                        if method == "GET":
                            response = await session.get(api_url, headers=headers, timeout=timeout)
                        elif method == "POST":
                            response = await session.post(api_url, headers=headers, json={}, timeout=timeout)
                        elif method == "PUT":
                            response = await session.put(api_url, headers=headers, json={}, timeout=timeout)
                        elif method == "DELETE":
                            response = await session.delete(api_url, headers=headers, timeout=timeout)
                        else:
                            return create_error_response(
                                "Unsupported method",
                                f"Method {method} is not supported for local testing",
                                additional_info={"is_local": True}
                            )
                            
                        async with response:
                            response_text = await response.text()
                            
                            # Try to parse the response as JSON if possible
                            response_json = None
                            try:
                                response_json = await response.json()
                            except:
                                # Not JSON or invalid JSON, that's fine
                                pass
                            
                            analysis_result = await deep_api_analysis(api_url, method=method)
                            logger.debug(f"Response status: {response.status}, text: {response_text[:100]}...")

                            # Check for common API response patterns that indicate errors
                            if response.status >= 400:
                                error_details = analysis_result.errors[0] if analysis_result.errors else None
                                error_message = error_details.error_message if error_details else f"Status {response.status}: {response_text}"
                                
                                # Try to extract more detailed error from JSON response
                                if response_json and isinstance(response_json, dict):
                                    if "error" in response_json:
                                        error_message = f"Status {response.status}: {response_json['error']}"
                                    elif "message" in response_json:
                                        error_message = f"Status {response.status}: {response_json['message']}"
                                
                                return {
                                    "platform": "Local Development",
                                    "error": error_message,
                                    "solution": "\n".join(error_details.suggested_fixes) if error_details else get_status_code_explanation(response.status),
                                    "repo_name": None,
                                    "file_path": None,
                                    "status": "error",
                                    "additional_info": {
                                        "severity": error_details.severity if error_details else "MEDIUM",
                                        "status_code": response.status,
                                        "performance_metrics": analysis_result.performance_metrics,
                                        "recommendations": analysis_result.recommendations,
                                        "is_local": True,
                                        "response_preview": response_text[:200] + ("..." if len(response_text) > 200 else "")
                                    }
                                }
                            
                            # API is healthy - return full analysis
                            return {
                                "platform": "Local Development",
                                "error": None,
                                "solution": None,
                                "repo_name": None,
                                "file_path": None,
                                "status": "healthy",
                                "additional_info": {
                                    "status_code": response.status,
                                    "latency_ms": int(analysis_result.performance_metrics.get("latency_ms", 0)),
                                    "content_type": response.headers.get("Content-Type", "unknown"),
                                    "performance_metrics": analysis_result.performance_metrics,
                                    "recommendations": analysis_result.recommendations,
                                    "is_local": True,
                                    "response_preview": response_text[:200] + ("..." if len(response_text) > 200 else "")
                                }
                            }
                            
                    except aiohttp.ClientResponseError as e:
                        # Handle specific status code errors
                        return create_error_response(
                            f"API endpoint error: {e.status}",
                            f"The API endpoint returned status code {e.status}. This typically means: " + 
                            get_status_code_explanation(e.status),
                            additional_info={
                                "error_type": "API_STATUS_ERROR",
                                "status_code": e.status,
                                "is_local": True,
                                "attempted_url": api_url
                            }
                        )
                    except aiohttp.ClientConnectorError as e:
                        # This means the server is running but couldn't establish a connection
                        # Likely the endpoint doesn't exist or there's a routing issue
                        return create_error_response(
                            "Endpoint connection error",
                            f"The server is running but the specific endpoint '{parsed_url.path}' couldn't be connected to. Check if this endpoint exists in your API.",
                            additional_info={
                                "error_type": "ENDPOINT_CONNECTION_ERROR",
                                "is_local": True,
                                "attempted_url": api_url,
                                "path": parsed_url.path,
                                "error_details": str(e)
                            }
                        )
                    except aiohttp.ClientError as e:
                        # Handle 404 and other error cases that might indicate endpoint doesn't exist
                        if "404" in str(e):
                            return create_error_response(
                                "Endpoint not found (404)",
                                f"The server is running on port {port}, but the endpoint '{parsed_url.path}' was not found. Check if you've implemented this endpoint or if there's a typo in the path.",
                                additional_info={
                                    "error_type": "ENDPOINT_NOT_FOUND",
                                    "is_local": True,
                                    "attempted_url": api_url,
                                    "path": parsed_url.path
                                }
                            )
                        
                        # Handle other client errors
                        return create_error_response(
                            f"Endpoint error: {str(e)}",
                            f"The server is running on port {port}, but there was an error accessing the endpoint '{parsed_url.path}'. This typically means the endpoint exists but there's an issue with it.",
                            additional_info={
                                "error_type": "ENDPOINT_ERROR",
                                "is_local": True,
                                "attempted_url": api_url,
                                "path": parsed_url.path,
                                "error_details": str(e)
                            }
                        )
                    except Exception as e:
                        # Catch any other exceptions when trying to access the endpoint
                        logger.error(f"Error accessing endpoint: {str(e)}")
                        return create_error_response(
                            "Endpoint access error",
                            f"The server is running on port {port}, but there was an error accessing the endpoint '{parsed_url.path}': {str(e)}",
                            additional_info={
                                "error_type": "ENDPOINT_ACCESS_ERROR",
                                "is_local": True,
                                "attempted_url": api_url,
                                "path": parsed_url.path,
                                "error_details": str(e)
                            }
                        )
                        
                except Exception as e:
                    logger.error(f"Local API request failed: {str(e)}")
                    # More specific error handling based on exception type
                    if "Cannot connect to host" in str(e) and "SSL" in str(e):
                        return create_error_response(
                            "SSL Connection Error",
                            "Cannot establish SSL connection. If you're using 'https://' for a local development server, try using 'http://' instead.",
                            additional_info={
                                "error_type": "SSL_ERROR",
                                "is_local": True,
                                "attempted_url": api_url,
                                "suggested_url": api_url.replace("https://", "http://") if api_url.startswith("https://") else api_url
                            }
                        )
                    return create_error_response(
                        f"Local API unreachable: {str(e)}",
                        "Ensure the local server is running and the endpoint exists. Check for typos in the URL.",
                        additional_info={
                            "error_type": "API_UNREACHABLE",
                            "is_local": True,
                            "error_details": str(e)
                        }
                    )
        else:
            # For non-local URLs, check if user accidentally entered a local path
            # This catches cases where users input incomplete URLs that don't resolve to localhost
            path_only = not parsed_url.netloc and parsed_url.path
            if path_only or (parsed_url.scheme and not parsed_url.netloc):
                return create_error_response(
                    "Invalid API URL format",
                    "The URL you provided doesn't appear to be a valid URL. If you're trying to test a local endpoint, " +
                    f"please specify it as 'localhost:{port or 3000}/{api_url.lstrip('/')}' or use the port parameter.",
                    additional_info={
                        "error_type": "URL_FORMAT_ERROR",
                        "is_local": False,
                        "attempted_url": api_url,
                        "suggested_url": f"http://localhost:{port or 3000}/{api_url.lstrip('/')}" if not '/' in api_url else f"http://localhost:{port or 3000}{api_url}"
                    }
                )
            
            # For cloud-hosted APIs, use existing deep analysis
            logger.debug(f"Analyzing cloud-hosted URL: {api_url}")
            analysis_result = await deep_api_analysis(api_url, method=method)
            if analysis_result.errors:
                error_details = analysis_result.errors[0]
                return {
                    "platform": detect_hosting_platform(api_url),
                    "error": f"{error_details.error_type}: {error_details.error_message}",
                    "solution": "\n".join(error_details.suggested_fixes),
                    "repo_name": None,
                    "file_path": None,
                    "status": "error",
                    "additional_info": {
                        "severity": error_details.severity,
                        "potential_causes": error_details.potential_causes,
                        "performance_metrics": analysis_result.performance_metrics,
                        "recommendations": analysis_result.recommendations,
                        "is_local": False
                    }
                }
            return {
                "platform": detect_hosting_platform(api_url),
                "error": None,
                "solution": None,
                "repo_name": None,
                "file_path": None,
                "status": "healthy",
                "additional_info": {
                    "performance_metrics": analysis_result.performance_metrics,
                    "recommendations": analysis_result.recommendations,
                    "is_local": False
                }
            }
    except Exception as e:
        logger.error(f"Unexpected error in check_api: {str(e)}\n{traceback.format_exc()}")
        return create_error_response(
            str(e),
            "An unexpected error occurred while analyzing the API",
            additional_info={"stack_trace": traceback.format_exc()}
        )

def create_error_response(error: str, solution: str, additional_info: Dict = None):
    """
    Helper function to create a consistent error response with CORS headers.
    """
    response = {
        "platform": "Unknown",
        "error": error,
        "solution": solution,
        "repo_name": None,
        "file_path": None,
        "status": "error",
        "additional_info": additional_info or {}
    }
    # Explicitly set CORS headers to allow frontend origin
    headers = {"Access-Control-Allow-Origin": "http://localhost:3000"}  # Adjust if frontend port differs
    return JSONResponse(content=response, headers=headers)

    
def get_status_code_explanation(status_code: int) -> str:
    """
    Returns a human-readable explanation for common HTTP status codes.
    """
    explanations = {
        400: "Bad Request - The server could not understand the request. Check your request format and parameters.",
        401: "Unauthorized - Authentication is required. Ensure you're providing proper credentials.",
        403: "Forbidden - You don't have permission to access this resource, even with authentication.",
        404: "Not Found - The requested resource doesn't exist. Check for typos in your URL path.",
        405: "Method Not Allowed - The API endpoint doesn't support this HTTP method.",
        408: "Request Timeout - The server timed out waiting for the request. Try again or check server load.",
        409: "Conflict - The request conflicts with the current state of the server. Possible data conflict.",
        422: "Unprocessable Entity - The server understands the content type but can't process the instructions.",
        429: "Too Many Requests - You've exceeded the rate limit. Slow down your requests.",
        500: "Internal Server Error - Something went wrong on the server. Check server logs.",
        501: "Not Implemented - The server doesn't support the functionality required.",
        502: "Bad Gateway - The server received an invalid response from an upstream server.",
        503: "Service Unavailable - The server is temporarily unable to handle the request.",
        504: "Gateway Timeout - The server timed out waiting for a response from an upstream server."
    }
    return explanations.get(status_code, f"HTTP status code {status_code}. Check your API implementation.")
    
# def create_error_response(error: str, solution: str, additional_info: Dict = None):
#     return {
#         "platform": "Unknown",
#         "error": error,
#         "solution": solution,
#         "repo_name": None,
#         "file_path": None,
#         "status": "error",
#         "additional_info": additional_info or {}
#     }




# Add these routes to your FastAPI application


from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from typing import Dict, Any
from urllib.parse import quote as urlencode
# Assuming you have a custom function for DeepSeek integration
from fastapi.staticfiles import StaticFiles  # If serving static files
from starlette.middleware.sessions import SessionMiddleware  # If using session middleware
import httpx  # If making HTTP requests in your DeepSeek function
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import os

# app.mount("/static", StaticFiles(directory="."), name="static")


# @app.get("/github-issue-creator")
# async def github_issue_creator(
#     request: Request,
#     token: str = Query(...),
#     title: str = Query(""),
#     body: str = Query("")
# ):
#     """Serve the GitHub issue creator HTML page with the provided parameters."""
#     # This ensures the HTML page is served directly from FastAPI
#     with open("github_issue.html", "r") as f:
#         html_content = f.read()
    
#     # Return the HTML content directly
#     return HTMLResponse(content=html_content)



@app.post("/apply-fix")
async def apply_fix(
    request: Request,
    fix_data: FixRequest
):
    """Modified endpoint to create GitHub issues with suggested fixes."""
    try:
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header"
            )
        
        token = auth_header.replace("Bearer ", "")
        
        # Validate the token with GitHub
        try:
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/json"
            }
            github_response = requests.get("https://api.github.com/user", headers=headers)
            
            if github_response.status_code != 200:
                # Return more detailed error message for debugging
                error_detail = {
                    "status_code": github_response.status_code,
                    "message": "GitHub token is invalid or expired. Please log in again.",
                    "github_response": github_response.text[:200]  # First 200 chars for debugging
                }
                raise HTTPException(
                    status_code=401,
                    detail=json.dumps(error_detail)
                )
        except requests.RequestException as token_error:
            print(f"Token validation error: {str(token_error)}")
            raise HTTPException(
                status_code=401,
                detail=f"Failed to validate GitHub token: {str(token_error)}"
            )
        
        # Generate solution using Hugging Face API instead of DeepSeek
        solution = await generate_solution_with_deepseek(fix_data.api_url, fix_data.fix_content)
        
        # Return the solution and token
        return {
            "status": "success",
            "message": "Ready to create GitHub issue",
            "solution": solution,
            "github_token": token
        }
        
    except HTTPException as he:
        # Pass through HTTP exceptions
        raise he
    except Exception as e:
        print(f"Error in apply_fix: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
async def generate_solution_with_deepseek(api_url: str, error_content: str):
    """Generate a solution using Hugging Face API (function name kept same for compatibility)."""
    try:
        import os
        import requests
        import re
        from datetime import datetime
        
        # Use API key from environment
        huggingface_api_key = os.getenv("DEEPSEEK_API")
        if not huggingface_api_key:
            raise ValueError("Hugging Face API key not found in environment variables")
        
        # Extract error type and message
        error_type = "Internal Server Error"  # Default
        error_details = error_content
        
        error_match = re.search(r"(\w+Error):\s*(.*?)(?:\n|$)", error_content)
        if error_match:
            error_type = error_match.group(1)
            error_details = error_match.group(2).strip()
        
        # Define default solutions for common errors - with minimal comments
        default_solutions = {
            "InternalServerError": """
const express = require('express');
const app = express();

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

app.get('/api/example', (req, res, next) => {
  try {
    res.json({ success: true, data: 'It works!' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/async-example', async (req, res, next) => {
  try {
    const result = await someAsyncFunction();
    res.json({ success: true, data: result });
  } catch (error) {
    next(error);
  }
});

app.use((err, req, res, next) => {
  console.error(`Error occurred: ${err.stack}`);
  
  const statusCode = err.statusCode || 500;
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  res.status(statusCode).json({
    error: {
      message: err.message || 'Internal Server Error',
      ...(isDevelopment && { stack: err.stack })
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}).on('error', (err) => {
  console.error('Server failed to start:', err);
});

async function someAsyncFunction() {
  return "async result";
}
"""
        }
        
        # Check if we have a default solution for this error type
        if error_type in default_solutions:
            # Format the solution with default content
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            formatted_solution = f"""# Solution for {error_type}

*Generated on: {timestamp}*

## Error Detected
{error_type}: {error_details}

## Suggested Fix
```javascript
// Fix for {api_url}
{default_solutions[error_type]}
```

## Implementation Steps
1. Add error handling middleware
2. Use try/catch in all route handlers
3. Handle Promise rejections properly
4. Add server startup error handling
5. Use a process manager like PM2 in production
"""
            return formatted_solution
        
        # If no default solution exists, continue with API call
        response = requests.post(
            "https://api-inference.huggingface.co/models/bigcode/starcoder",
            headers={
                "Authorization": f"Bearer {huggingface_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "inputs": f"""
                Fix the Node.js API endpoint that's returning "{error_type}: {error_details}" at URL {api_url}.
                Provide clean code with minimal comments. Focus on proper error handling.
                """,
                "parameters": {
                    "temperature": 0.3,
                    "max_new_tokens": 1500,
                    "return_full_text": False,
                    "top_k": 30,
                    "top_p": 0.9
                }
            }
        )
        
        if response.status_code != 200:
            raise ValueError(f"API error: {response.status_code} - {response.text}")
        
        result = response.json()
        
        # Extract solution text from response
        solution_text = ""
        if isinstance(result, list) and len(result) > 0:
            solution_text = result[0].get("generated_text", "")
        elif isinstance(result, dict):
            solution_text = result.get("generated_text", "")
        
        # Extract code blocks
        code_blocks = re.findall(r"```(?:javascript|js)?\s*([\s\S]*?)```", solution_text)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        formatted_solution = f"""# Solution for {error_type}

*Generated on: {timestamp}*

## Error Detected
{error_type}: {error_details}

## Suggested Fix
```javascript
// Fix for {api_url}
"""
        
        # Add the code solution
        if code_blocks:
            longest_block = max(code_blocks, key=len)
            clean_code = longest_block.strip().replace("```", "")
            formatted_solution += clean_code
        else:
            if error_type in default_solutions:
                formatted_solution += default_solutions[error_type]
            else:
                formatted_solution += solution_text.strip()
        
        # Close the code block and add footer
        formatted_solution += "\n```\n\nGenerated by CloudPatch AI"
        
        return formatted_solution

    except Exception as e:
        error_message = str(e)
        print(f"Error generating solution: {error_message}")
        return f"# Error Report\n\nUnable to generate solution: {error_message}"

@app.get("/github-issue-creator")
async def github_issue_creator(
    request: Request,
    token: str = Query(...),
    title: str = Query(""),
    body: str = Query("")
):
    """Serve the GitHub issue creator HTML page with the provided parameters."""
    try:
        # Pre-fetching in parallel to improve performance
        async def validate_token():
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/json"
            }
            return await request.app.state.http_client.get(
                "https://api.github.com/user", 
                headers=headers
            )
        
        async def fetch_repos(user_data):
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/json"
            }
            return await request.app.state.http_client.get(
                "https://api.github.com/user/repos?sort=updated&per_page=100",
                headers=headers
            )
        
        # Set up async HTTP client if not already present
        if not hasattr(request.app.state, "http_client"):
            import aiohttp
            request.app.state.http_client = aiohttp.ClientSession()
        
        # Execute token validation 
        github_response = await validate_token()
        
        if github_response.status != 200:
            # If token is invalid, return error page with GitHub-style dark theme
            error_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Error</title>
                <style>
                    body {{ 
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                        text-align: center;
                        padding: 50px;
                        background: linear-gradient(135deg, #0d1117, #161b22);
                        color: #c9d1d9;
                        margin: 0;
                    }}
                    .card {{
                        background-color: #0d1117;
                        border-radius: 6px;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                        padding: 24px;
                        max-width: 400px;
                        margin: 0 auto;
                        border: 1px solid #30363d;
                    }}
                    .error {{ 
                        color: #f85149;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }}
                    .button {{ 
                        padding: 8px 16px;
                        background-color: #238636;
                        color: white; 
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 14px;
                        font-weight: 500;
                        transition: background-color 0.2s;
                    }}
                    .button:hover {{ 
                        background-color: #2ea043;
                    }}
                </style>
            </head>
            <body>
                <div class="card">
                    <h1 class="error">Authentication Error</h1>
                    <p>Your GitHub token is invalid or has expired.</p>
                    <p>Please return to the main application and login again.</p>
                    <button class="button" onclick="window.close()">Close Window</button>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=error_html)
        
        # Get user data for personalization
        user_data = await github_response.json()
        username = user_data.get("login", "GitHub User")
        
        # Get user's repositories in parallel
        repos_response = await fetch_repos(user_data)
        
        if repos_response.status != 200:
            return HTMLResponse(content=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Repository Error</title>
                <style>
                    body {{ 
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                        text-align: center;
                        padding: 30px;
                        background: linear-gradient(135deg, #0d1117, #161b22);
                        color: #c9d1d9;
                        margin: 0;
                    }}
                    .card {{
                        background-color: #0d1117;
                        border-radius: 6px;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                        padding: 24px;
                        max-width: 600px;
                        margin: 0 auto;
                        border: 1px solid #30363d;
                    }}
                    .error {{ 
                        color: #f85149;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }}
                    pre {{ 
                        text-align: left;
                        background: #161b22;
                        padding: 16px;
                        border-radius: 6px;
                        overflow: auto;
                        color: #8b949e;
                        border: 1px solid #30363d;
                        font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
                    }}
                    .button {{ 
                        padding: 8px 16px;
                        background-color: #238636;
                        color: white; 
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 14px;
                        font-weight: 500;
                    }}
                    .button:hover {{ 
                        background-color: #2ea043;
                    }}
                </style>
            </head>
            <body>
                <div class="card">
                    <h1 class="error">Failed to fetch repositories</h1>
                    <p>Status code: {repos_response.status}</p>
                    <pre>{await repos_response.text()}</pre>
                    <button class="button" onclick="window.close()">Close Window</button>
                </div>
            </body>
            </html>
            """)
        
        repos = await repos_response.json()
        
        # Use a more optimized approach to build HTML - using a truncated list initially
        # and loading the rest asynchronously
        top_repos = repos[:10]  # Show first 10 repos immediately
        remaining_repos = repos[10:]
        
        # Build HTML for repository selection and issue creation with GitHub dark theme
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Create GitHub Issue</title>
            <style>
                :root {{
                    --color-bg-primary: #0d1117;
                    --color-bg-secondary: #161b22;
                    --color-border: #30363d;
                    --color-text-primary: #c9d1d9;
                    --color-text-secondary: #8b949e;
                    --color-btn-primary: #238636;
                    --color-btn-hover: #2ea043;
                    --color-header-bg: #161b22;
                    --color-accent: #58a6ff;
                    --color-hover: #21262d;
                    --color-selected: #0d419d;
                }}
                
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background: linear-gradient(135deg, var(--color-bg-primary), var(--color-bg-secondary));
                    color: var(--color-text-primary);
                    min-height: 100vh;
                }}
                
                .container {{ 
                    max-width: 700px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                
                header {{
                    padding: 16px 0;
                    border-bottom: 1px solid var(--color-border);
                    margin-bottom: 24px;
                }}
                
                h1, h2 {{ 
                    color: var(--color-text-primary);
                    font-weight: 600;
                }}
                
                h1 {{
                    font-size: 24px;
                    margin: 0 0 8px 0;
                }}
                
                .welcome-text {{
                    color: var(--color-text-secondary);
                    margin-bottom: 24px;
                }}
                
                .card {{
                    background-color: var(--color-bg-primary);
                    border: 1px solid var(--color-border);
                    border-radius: 6px;
                    margin-bottom: 24px;
                    overflow: hidden;
                }}
                
                .card-header {{
                    background-color: var(--color-header-bg);
                    padding: 16px;
                    border-bottom: 1px solid var(--color-border);
                    font-weight: 600;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                
                .search-input {{
                    background-color: var(--color-bg-primary);
                    border: 1px solid var(--color-border);
                    border-radius: 4px;
                    padding: 6px 10px;
                    color: var(--color-text-primary);
                    width: 200px;
                    font-size: 14px;
                }}
                
                .search-input:focus {{
                    outline: none;
                    border-color: var(--color-accent);
                }}
                
                .repo-list {{ 
                    max-height: 300px;
                    overflow-y: auto;
                }}
                
                .repo-list-loading {{
                    padding: 20px;
                    text-align: center;
                    color: var(--color-text-secondary);
                }}
                
                .repo-item {{ 
                    padding: 12px 16px;
                    border-bottom: 1px solid var(--color-border);
                    cursor: pointer;
                    transition: background-color 0.2s;
                }}
                
                .repo-item:hover {{ 
                    background-color: var(--color-hover);
                }}
                
                .repo-item:last-child {{ 
                    border-bottom: none;
                }}
                
                .repo-name {{ 
                    font-weight: 600;
                    color: var(--color-accent);
                }}
                
                .repo-desc {{ 
                    color: var(--color-text-secondary);
                    font-size: 12px;
                    margin-top: 4px;
                }}
                
                .issue-form {{ 
                    display: none;
                }}
                
                .issue-form.active {{ 
                    display: block;
                }}
                
                .form-group {{
                    margin-bottom: 16px;
                }}
                
                label {{ 
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    color: var(--color-text-primary);
                }}
                
                input[type="text"], textarea {{ 
                    width: 100%;
                    padding: 8px 12px;
                    background-color: var(--color-bg-primary);
                    border: 1px solid var(--color-border);
                    border-radius: 6px;
                    color: var(--color-text-primary);
                    font-size: 14px;
                    box-sizing: border-box;
                }}
                
                input[type="text"]:focus, textarea:focus {{
                    outline: none;
                    border-color: var(--color-accent);
                    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.3);
                }}
                
                textarea {{ 
                    min-height: 200px;
                    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
                    line-height: 1.5;
                    resize: vertical;
                }}
                
                button {{ 
                    background-color: var(--color-btn-primary);
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 14px;
                    font-weight: 500;
                    transition: background-color 0.2s;
                }}
                
                button:hover {{ 
                    background-color: var(--color-btn-hover);
                }}
                
                button:disabled {{
                    opacity: 0.6;
                    cursor: not-allowed;
                }}
                
                .selected-repo {{ 
                    padding: 12px 16px;
                    background-color: var(--color-selected);
                    border-radius: 6px;
                    margin-bottom: 16px;
                    font-size: 14px;
                    color: white;
                }}
                
                /* Loading indicator styles */
                .loading-spinner {{
                    display: inline-block;
                    width: 20px;
                    height: 20px;
                    border: 2px solid rgba(255,255,255,0.2);
                    border-radius: 50%;
                    border-top-color: var(--color-accent);
                    animation: spin 1s linear infinite;
                    margin-right: 8px;
                }}
                
                @keyframes spin {{
                    to {{ transform: rotate(360deg); }}
                }}
                
                .hidden {{
                    display: none;
                }}
                
                /* Frequently used repos section */
                .frequent-repos {{
                    margin-bottom: 16px;
                    padding: 8px 16px;
                    background-color: var(--color-header-bg);
                    border-radius: 6px;
                    border: 1px solid var(--color-border);
                }}
                
                .frequent-repos-title {{
                    font-size: 14px;
                    color: var(--color-text-secondary);
                    margin-bottom: 8px;
                }}
                
                .frequent-repo-item {{
                    display: inline-block;
                    margin-right: 8px;
                    margin-bottom: 8px;
                    padding: 4px 10px;
                    background-color: var(--color-bg-primary);
                    border: 1px solid var(--color-border);
                    border-radius: 16px;
                    font-size: 12px;
                    cursor: pointer;
                    transition: background-color 0.2s;
                }}
                
                .frequent-repo-item:hover {{
                    background-color: var(--color-hover);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Create solution for github repo : </h1>
                </header>
                
                <div class="welcome-text">
                    Welcome, <strong>{username}</strong>! Select a repository to create a solution:
                </div>
                
                <!-- Auto-populated form with URL params -->
                <div id="issue-form" class="issue-form">
                    <div id="selected-repo" class="selected-repo"></div>
                    
                    <div class="card">
                        <div class="card-header">New issue</div>
                        <form id="github-issue-form" style="padding: 16px;">
                            <div class="form-group">
                                <label for="issue-title">Title</label>
                                <input type="text" id="issue-title" value="{title}" placeholder="Issue title" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="issue-body">Description</label>
                                <textarea id="issue-body" placeholder="Describe the issue in detail..." required>{body}</textarea>
                            </div>
                            
                            <button type="submit">Create issue</button>
                        </form>
                    </div>
                </div>
                
                <!-- Frequently used repositories (will be populated from localStorage) -->
                <div id="frequent-repos" class="frequent-repos hidden">
                    <div class="frequent-repos-title">Recently used repositories:</div>
                    <div id="frequent-repos-list"></div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <span>Your repositories</span>
                        <input type="text" id="repo-search" class="search-input" placeholder="Search repositories..." autocomplete="off">
                    </div>
                    <div id="repo-list" class="repo-list">
                        {''.join([f'''
                        <div class="repo-item" data-owner="{repo["owner"]["login"]}" data-repo="{repo["name"]}">
                            <div class="repo-name">{repo["name"]}</div>
                            <div class="repo-desc">{repo.get("description", "")}</div>
                        </div>
                        ''' for repo in top_repos])}
                        <div id="loading-more" class="repo-list-loading hidden">
                            <div class="loading-spinner"></div> Loading more repositories...
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Store the GitHub token
                const token = "{token}";
                let selectedOwner = "";
                let selectedRepo = "";
                let allRepos = [];
                
                // Preload the remaining repositories data
                const remainingRepos = {json.dumps(remaining_repos)};
                
                // Store recently used repositories in localStorage
                const STORAGE_KEY = 'github_frequent_repos';
                
                // Function to get frequent repos from localStorage
                function getFrequentRepos() {{
                    try {{
                        const stored = localStorage.getItem(STORAGE_KEY);
                        return stored ? JSON.parse(stored) : [];
                    }} catch (e) {{
                        console.error('Error reading from localStorage:', e);
                        return [];
                    }}
                }}
                
                // Function to save a repo to frequent repos
                function saveRepoToFrequent(owner, repo) {{
                    try {{
                        let repos = getFrequentRepos();
                        
                        // Check if already exists
                        const existingIndex = repos.findIndex(r => r.owner === owner && r.name === repo);
                        if (existingIndex !== -1) {{
                            // Move to front if exists
                            const existing = repos.splice(existingIndex, 1)[0];
                            repos.unshift({{...existing, timestamp: Date.now()}});
                        }} else {{
                            // Add to front if new
                            repos.unshift({{
                                owner,
                                name: repo,
                                timestamp: Date.now()
                            }});
                            
                            // Keep only most recent 5
                            repos = repos.slice(0, 5);
                        }}
                        
                        localStorage.setItem(STORAGE_KEY, JSON.stringify(repos));
                        return repos;
                    }} catch (e) {{
                        console.error('Error saving to localStorage:', e);
                        return [];
                    }}
                }}
                
                // Display frequent repos
                function displayFrequentRepos() {{
                    const repos = getFrequentRepos();
                    const container = document.getElementById('frequent-repos-list');
                    container.innerHTML = '';
                    
                    if (repos.length > 0) {{
                        document.getElementById('frequent-repos').classList.remove('hidden');
                        
                        repos.forEach(repo => {{
                            const element = document.createElement('div');
                            element.className = 'frequent-repo-item';
                            element.textContent = `${{repo.owner}}/${{repo.name}}`;
                            element.addEventListener('click', () => selectRepo(repo.owner, repo.name));
                            container.appendChild(element);
                        }});
                    }} else {{
                        document.getElementById('frequent-repos').classList.add('hidden');
                    }}
                }}
                
                // Function to filter repositories
                function filterRepos(searchTerm) {{
                    const repoList = document.getElementById('repo-list');
                    const items = repoList.getElementsByClassName('repo-item');
                    const searchTermLower = searchTerm.toLowerCase();
                    
                    // Remove all existing repository items (except loading indicator)
                    const loadingMore = document.getElementById('loading-more');
                    while (repoList.firstChild && repoList.firstChild !== loadingMore) {{
                        repoList.removeChild(repoList.firstChild);
                    }}
                    
                    // If we have remaining repos loaded in memory, use those too for search
                    const fullRepoList = [...{json.dumps(top_repos)}, ...remainingRepos];
                    
                    // Filter and add matching repos
                    const filteredRepos = fullRepoList.filter(repo => 
                        repo.name.toLowerCase().includes(searchTermLower) ||
                        (repo.description && repo.description.toLowerCase().includes(searchTermLower))
                    );
                    
                    // Add filtered repos back to the DOM
                    filteredRepos.forEach(repo => {{
                        const repoElement = document.createElement('div');
                        repoElement.className = 'repo-item';
                        repoElement.setAttribute('data-owner', repo.owner.login);
                        repoElement.setAttribute('data-repo', repo.name);
                        
                        const nameElement = document.createElement('div');
                        nameElement.className = 'repo-name';
                        nameElement.textContent = repo.name;
                        repoElement.appendChild(nameElement);
                        
                        if (repo.description) {{
                            const descElement = document.createElement('div');
                            descElement.className = 'repo-desc';
                            descElement.textContent = repo.description;
                            repoElement.appendChild(descElement);
                        }}
                        
                        repoList.insertBefore(repoElement, loadingMore);
                    }});
                    
                    // Attach click event to all repo items
                    setupRepoClickEvents();
                }}
                
                function setupRepoClickEvents() {{
                    const repoItems = document.querySelectorAll('.repo-item');
                    repoItems.forEach(item => {{
                        // Only add event listener if it doesn't already have one
                        if (!item.hasEventListener) {{
                            item.hasEventListener = true;
                            item.addEventListener('click', function() {{
                                const owner = this.getAttribute('data-owner');
                                const repo = this.getAttribute('data-repo');
                                selectRepo(owner, repo);
                            }});
                        }}
                    }});
                }}
                
                function selectRepo(owner, repo) {{
                    selectedOwner = owner;
                    selectedRepo = repo;
                    
                    // Save to frequent repos
                    saveRepoToFrequent(owner, repo);
                    displayFrequentRepos();
                    
                    // Show the form and update selected repo display
                    document.getElementById("issue-form").classList.add("active");
                    document.getElementById("selected-repo").textContent = `Creating issue in: ${{owner}}/${{repo}}`;
                    
                    // Scroll to the form
                    document.getElementById("issue-form").scrollIntoView({{ behavior: "smooth" }});
                }}
                
                // Initialize the page and load the remaining repos asynchronously
                document.addEventListener('DOMContentLoaded', function() {{
                    // Set up search functionality
                    const searchInput = document.getElementById('repo-search');
                    searchInput.addEventListener('input', function() {{
                        filterRepos(this.value);
                    }});
                    
                    // Set up click events for initial repos
                    setupRepoClickEvents();
                    
                    // Load and display frequent repos
                    displayFrequentRepos();
                    
                    // Append the remaining repos with a slight delay to not block rendering
                    if (remainingRepos.length > 0) {{
                        const loadingIndicator = document.getElementById('loading-more');
                        loadingIndicator.classList.remove('hidden');
                        
                        setTimeout(() => {{
                            const repoList = document.getElementById('repo-list');
                            remainingRepos.forEach(repo => {{
                                const repoElement = document.createElement('div');
                                repoElement.className = 'repo-item';
                                repoElement.setAttribute('data-owner', repo.owner.login);
                                repoElement.setAttribute('data-repo', repo.name);
                                
                                const nameElement = document.createElement('div');
                                nameElement.className = 'repo-name';
                                nameElement.textContent = repo.name;
                                repoElement.appendChild(nameElement);
                                
                                if (repo.description) {{
                                    const descElement = document.createElement('div');
                                    descElement.className = 'repo-desc';
                                    descElement.textContent = repo.description;
                                    repoElement.appendChild(descElement);
                                }}
                                
                                repoList.insertBefore(repoElement, loadingIndicator);
                            }});
                            
                            // Hide loading indicator
                            loadingIndicator.classList.add('hidden');
                            
                            // Setup click events for new repos
                            setupRepoClickEvents();
                        }}, 50); // Small delay to allow the page to render first
                    }}
                }});
                
                document.getElementById("github-issue-form").addEventListener("submit", async function(e) {{
                    e.preventDefault();
                    
                    if (!selectedOwner || !selectedRepo) {{
                        alert("Please select a repository first");
                        return;
                    }}
                    
                    const title = document.getElementById("issue-title").value;
                    const body = document.getElementById("issue-body").value;
                    
                    if (!title || !body) {{
                        alert("Title and description are required");
                        return;
                    }}
                    
                    try {{
                        const submitButton = document.querySelector('button[type="submit"]');
                        submitButton.disabled = true;
                        submitButton.innerHTML = '<div class="loading-spinner"></div> Creating issue...';
                        
                        // Create the issue using GitHub API with a timeout to prevent hanging
                        const controller = new AbortController();
                        const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout
                        
                        const response = await fetch(`https://api.github.com/repos/${{selectedOwner}}/${{selectedRepo}}/issues`, {{
                            method: "POST",
                            headers: {{
                                "Authorization": `token ${{token}}`,
                                "Accept": "application/vnd.github.v3+json",
                                "Content-Type": "application/json"
                            }},
                            body: JSON.stringify({{
                                title: title,
                                body: body
                            }}),
                            signal: controller.signal
                        }});
                        
                        clearTimeout(timeoutId);
                        
                        if (!response.ok) {{
                            const errorData = await response.json();
                            throw new Error(`GitHub API error: ${{response.status}} - ${{errorData.message || 'Unknown error'}}`);
                        }}
                        
                        const issue = await response.json();
                        
                        // Show success message
                        alert(`Issue #${{issue.number}} created successfully!`);
                        
                        // Notify opener window of success
                        if (window.opener) {{
                            window.opener.postMessage({{
                                type: "issue-created",
                                issueNumber: issue.number,
                                issueUrl: issue.html_url
                            }}, "*");
                        }}
                        
                        // Navigate to the created issue
                        window.location.href = issue.html_url;
                        
                    }} catch (error) {{
                        console.error("Error creating issue:", error);
                        alert(`Failed to create issue: ${{error.message}}`);
                        
                        const submitButton = document.querySelector('button[type="submit"]');
                        submitButton.disabled = false;
                        submitButton.textContent = "Create issue";
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        # Return the HTML content with explicit Content-Type
        return HTMLResponse(
            content=html_content, 
            headers={"Content-Type": "text/html; charset=utf-8"}
        )
    except Exception as e:
        import traceback
        error_message = f"Error: {str(e)}\n{traceback.format_exc()}"
        print(error_message)
        return HTMLResponse(
            content=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error</title>
                <style>
                    body {{ 
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                        padding: 30px;
                        background: linear-gradient(135deg, #0d1117, #161b22);
                        color: #c9d1d9;
                        margin: 0;
                    }}
                    .card {{
                        background-color: #0d1117;
                        border-radius: 6px;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                        padding: 24px;
                        max-width: 700px;
                        margin: 0 auto;
                        border: 1px solid #30363d;
                    }}
                    .error {{ 
                        color: #f85149;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }}
                    pre {{ 
                        background: #161b22;
                        padding: 16px;
                        border-radius: 6px;
                        overflow: auto;
                        color: #8b949e;
                        font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
                        line-height: 1.5;
                        max-height: 400px;
                        border: 1px solid #30363d;
                    }}
                    .button {{ 
                        padding: 8px 16px;
                        background-color: #238636;
                        color: white; 
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        margin-top: 16px;
                        font-size: 14px;
                        font-weight: 500;
                    }}
                    .button:hover {{ 
                        background-color: #2ea043;
                    }}
                </style>
            </head>
            <body>
                <div class="card">
                    <h1 class="error">Error</h1>
                    <pre>{error_message}</pre>
                    <button class="button" onclick="window.close()">Close Window</button>
                </div>
            </body>
            </html>
            """,
            headers={"Content-Type": "text/html; charset=utf-8"}
        )
    
# Add a new route to serve the HTML page
# @app.get("/github-issue-creator")
# async def github_issue_creator(
#     request: Request,
#     token: str = Query(...),
#     title: str = Query(""),
#     body: str = Query("")
# ):
#     """Serve the GitHub issue creator HTML page with the provided parameters."""
#     # This ensures the HTML page is served directly from FastAPI
#     with open("github_issue.html", "r") as f:
#         html_content = f.read()
    
#     # Return the HTML content directly
#     return HTMLResponse(content=html_content)



@app.post("/send-fix")
async def send_fix(request: FixRequest, session: Request):
    token = session.session.get("github_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if not request.repo_name or not request.file_path:
        raise HTTPException(status_code=400, detail="Repository name and file path are required")
    
    try:
        headers = {"Authorization": f"token {token}"}
        
        # Get current file content
        file_url = f"https://api.github.com/repos/{request.repo_name}/contents/{request.file_path}"
        file_response = requests.get(file_url, headers=headers)
        file_response.raise_for_status()
        file_data = file_response.json()
        
        # Prepare update
        encoded_content = base64.b64encode(request.fix_content.encode()).decode()
        update_data = {
            "message": "CloudPatch.ai: Applied automated fix",
            "content": encoded_content,
            "sha": file_data["sha"]
        }
        
        # Send update
        update_response = requests.put(file_url, headers=headers, json=update_data)
        update_response.raise_for_status()
        
        return {
            "message": "Fix applied successfully",
            "commit_url": update_response.json().get("commit", {}).get("html_url")
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to apply fix: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# venv\Scripts\activate
# uvicorn main:app --reload

