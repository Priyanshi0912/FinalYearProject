


from django.shortcuts import render
from django.http import HttpResponse
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from django.utils.timezone import make_aware
import re


def home(request):
    return render(request, 'home.html')


def grading_system(request):
    return render(request, 'grading_system.html')


def security_recommendations(request):
    return render(request, 'recommendations.html')

# Function to extract the hostname from a URL or directly use the hostname
def extract_hostname(url):
    # Remove 'http://' or 'https://' from the URL and strip any trailing slashes
    hostname = re.sub(r'^https?://', '', url).strip('/')
    return hostname

# Function to retrieve the server certificate
def get_server_certificate(hostname, port=443):
    # Extract hostname from the URL or direct hostname input
    hostname = extract_hostname(hostname)

    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            der_cert = secure_sock.getpeercert(binary_form=True)
            return x509.load_der_x509_certificate(der_cert, default_backend())
        
def check_trusted_ca(cert):
    # List of common trusted CAs
    trusted_cas = {
        "DigiCert",
        "GlobalSign",
        "Entrust",
        "Sectigo",
        "GoDaddy",
        "Let's Encrypt",
        "Thawte",
        "GeoTrust",
        "VeriSign",
        "Symantec",
        "Buypass",
        "QuoVadis",
        "Trustwave",
        "Certum",
        "Network Solutions"
    }

    # Extract issuer's name from the certificate
    issuer_name = cert.issuer.rfc4514_string()

    # Check if the issuer's name is in the list of trusted CAs
    # This may require more specific parsing based on the issuer's name format
    for ca in trusted_cas:
        if ca in issuer_name:
            return None  # Trusted CA found
        

    return f"Warning: The certificate is issued by an untrusted CA: {issuer_name}"



def check_certificate_validity(cert):
    # Get the validity dates from the certificate
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    # Ensure not_before and not_after are aware datetime objects
    if not_before.tzinfo is None:
        not_before = make_aware(not_before)
    if not_after.tzinfo is None:
        not_after = make_aware(not_after)

    # Check if the certificate is within the validity period
    current_time = datetime.now(timezone.utc)

    # Check if the certificate is currently valid
    if current_time < not_before or current_time > not_after:
        return "Warning: The certificate is not currently valid."

    # Check the maximum lifespan for certificates issued after 1st September 2020
    if not_before > datetime(2020, 9, 1, tzinfo=timezone.utc):
        max_lifespan = (not_after - not_before).days
        if max_lifespan > 398:
            return f"Warning: The certificate has a maximum lifespan of {max_lifespan} days, exceeding the limit of 398 days."

    return None  # No warnings


def check_protocol_version(hostname, port=443):
    context = ssl.create_default_context()
    warning_list = []
    protocol_scores = {
        'SSLv2': 0,
        'SSLv3': 20,
        'TLSv1': 60,
        'TLSv1.1': 80,
        'TLSv1.2': 100,
        'TLSv1.3': 100,
    }

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            protocol_version = secure_sock.version()
            score = protocol_scores.get(protocol_version, 0)

            if protocol_version in ['SSLv2', 'SSLv3']:
                warning_list.append(f"Warning: {protocol_version} is deprecated due to serious vulnerabilities (e.g., Poodle).")
            elif protocol_version in ['TLSv1', 'TLSv1.1']:
                warning_list.append(f"Warning: {protocol_version} suffers from vulnerabilities and should not be used.")

            return protocol_version, score, warning_list


def check_key_size(cert):
    public_key = cert.public_key()
    key_size = public_key.key_size

    key_score = (
        10 if key_size < 512 else
        20 if key_size < 1024 else
        50 if key_size < 2048 else
        90 if key_size < 4096 else
        100
    )

    # Add warning for weak key sizes
    key_warning = None
    if key_size < 2048:
        key_warning = f"Weak key size: {key_size} bits (should be at least 2048 bits)"

    return key_size, key_score, key_warning


# def check_cipher_strength(hostname, port=443):
#     context = ssl.create_default_context()
#     with socket.create_connection((hostname, port)) as sock:
#         with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
#             cipher = secure_sock.cipher()
#             cipher_name = cipher[0] if cipher else None
            
#             # Example scores based on typical cipher names
#             if cipher_name:
#                 cipher_scores = {
#                     'AES256-GCM-SHA384': 100,
#                     'AES128-GCM-SHA256': 100,
#                     'AES256-SHA256': 80,
#                     'RC4-SHA': 30,
#                     'EXP-RC4-MD5': 0,
#                 }
#                 score = cipher_scores.get(cipher_name, 0)
#             else:
#                 score = 0
            
#             return score


def calculate_overall_score(protocol_score, key_score, cipher_score):
    overall_score = (0.3 * protocol_score) + (0.3 * key_score) + (0.4 * cipher_score)
    return overall_score


# Function to determine grade based on overall score
def grade_certificate(overall_score):
    # Determine grade based on overall score
    if overall_score < 20:
        return 'F'
    elif overall_score < 35:
        return 'E'
    elif overall_score < 50:
        return 'D'
    elif overall_score < 65:
        return 'C'
    elif overall_score < 80:
        return 'B'
    else:  # overall_score >= 80
        return 'A'


# View to analyze the SSL certificate
def analyze_certificate(request):
    if request.method == 'POST':
        hostname = request.POST.get('hostname')
        
        # Ensure the hostname is extracted correctly
        hostname = extract_hostname(hostname)  # This should strip 'http:// or 'https://'
        
        try:
            cert = get_server_certificate(hostname)

            warnings = []

            # Check for trusted CA
            ca_warning = check_trusted_ca(cert)
            if ca_warning:
                warnings.append(ca_warning)



            # Check certificate validity
            validity_warning = check_certificate_validity(cert)
            if validity_warning:
                warnings.append(validity_warning)


            # Analyze protocol and cipher
            protocol_version, protocol_score, protocol_warnings = check_protocol_version(hostname)
            #cipher_score = check_cipher_strength(hostname)

            # Combine warnings from protocol check
            warnings.extend(protocol_warnings)

            # Check key size and get the key size score
            key_size, key_score, key_warning = check_key_size(cert)
            if key_warning:
                warnings.append(key_warning)

            # Calculate overall score
            overall_score = calculate_overall_score(protocol_score, key_score, 100)#cipher_score)

            # Determine the grade
            grade = grade_certificate(overall_score)
            signature_algorithm = cert.signature_algorithm_oid._name
            # Set bar percentages based on the results from the functions
            bar_percentages = {
                'certificate': overall_score ,#80 if grade == 'A' else 60 if grade == 'B' else 40,
                'protocol_support': protocol_score,  # Use the score from check_protocol_version
                'key_exchange': key_score,            # Use the score from check_key_size
                'cipher_strength': 100,#cipher_score,      # Use the score from check_cipher_strength
            }

            # Collect certificate information for rendering
            details = {
                'warnings': warnings,
                'bar_percentages': bar_percentages,
                'hostname': hostname,
                'protocol_version':protocol_version,
                'not_before': cert.not_valid_before,  
                'not_after': cert.not_valid_after,
                'cert_version': cert.version,
                'serial_number': cert.serial_number,
                'issuer': cert.issuer.rfc4514_string(),
                'key_size': key_size,
                'signature_algorithm': signature_algorithm,
                'subject': cert.subject.rfc4514_string(),
                'grade': grade,
                'overall_score': overall_score,
            }

            return render(request, 'analyze.html', details)

        except ssl.SSLError as e:
            return HttpResponse(f"SSL Error: Unable to establish a secure connection to {hostname}")
        except socket.gaierror:
            return HttpResponse(f"Error: Unable to resolve hostname {hostname}")
        except socket.error as e:
            return HttpResponse(f"Connection Error: Unable to connect to {hostname}")
        except Exception as e:
            return HttpResponse(f"Unexpected error analyzing the certificate: {str(e)}")

    return render(request, 'analyze.html')