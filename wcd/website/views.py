


from django.shortcuts import render,redirect
from django.http import HttpResponse
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from django.utils.timezone import make_aware
import re
from django.core.mail import send_mail
from django.conf import settings
from .models import NotificationSettings
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from .models import AnalyzedURL

def home(request):
    return render(request, 'home.html')

from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('home')  # Redirect to home page after logout

def grading_system(request):
    return render(request, 'grading_system.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('analyze_certificate')  # Redirect to the analysis page after successful login
        else:
            # Handle invalid login (e.g., show an error message)
            return render(request, 'login.html', {'error': 'Invalid credentials'})

    return render(request, 'login.html')



def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)  # Create a form instance with POST data
        if form.is_valid():  # Check if the form is valid
            form.save()  # Save the new user
            messages.success(request, 'Registration successful! You can now log in.')  # Optional success message
            return redirect('login_view')  # Redirect to the login page after successful registration
    else:
        form = UserCreationForm()  # Create a blank form for GET requests

    return render(request, 'register.html', {'form': form})


from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login


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
        "Google Trust Services",
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
    
    #protocol version with score
    protocol_scores = {
        'SSLv2': 0,
        'SSLv3': 80,
        'TLSv1': 90,
        'TLSv1.1': 95,
        'TLSv1.2': 100,
        'TLSv1.3': 100,
    }

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            protocol_version = secure_sock.version()
            score = protocol_scores.get(protocol_version, 0)

            # Add warnings based on the protocol version
            if protocol_version == 'SSLv2':
                warning_list.append(f"Warning: {protocol_version} is deprecated due to serious vulnerabilities.")
            elif protocol_version == 'SSLv3':
                warning_list.append(f"Warning: {protocol_version} is deprecated due to the Poodle vulnerability.")
            elif protocol_version in ['TLSv1', 'TLSv1.1']:
                warning_list.append(f"Warning: {protocol_version} suffers from vulnerabilities and should not be used.")

            return protocol_version, score, warning_list


def check_key_size(cert):
    public_key = cert.public_key()
    key_size = public_key.key_size

    # Update key_score based on provided scoring rules
    key_score = (
        0 if key_size < 512 else
        20 if key_size == 512 else
        40 if key_size < 1024 else
        80 if key_size < 2048 else
        90 if key_size < 4096 else
        100
    )

    # Add warning for weak key sizes
    key_warning = None
    if key_size < 2048:
        key_warning = f"Weak key size: {key_size} bits (should be at least 2048 bits)"

    return key_size, key_score, key_warning

import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def check_signature_algorithm_strength(hostname, port=443):
    # Dictionary of signature algorithms and scores based on security best practices
    signature_scores = {
        'ecdsa-with-SHA384': 100,
        'ecdsa-with-SHA256': 95,
        'rsaPSSwithSHA512': 90,
        'rsaPSSwithSHA256': 85,
        'sha256WithRSAEncryption': 80,
        'sha384WithRSAEncryption': 80,
        'sha1WithRSAEncryption': 20,
        'sha1WithDSA': 10,
        'md5WithRSAEncryption': 0,
        'sha1WithECDSA': 15
    }
    
    try:
        # Establish a connection and retrieve the server certificate
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                der_cert = secure_sock.getpeercert(binary_form=True)
                
                # Load the certificate using cryptography library to get the signature algorithm
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                # Get the signature algorithm name
                sig_alg_name = cert.signature_algorithm_oid._name
                print(f"Signature Algorithm in certificate: {sig_alg_name}")
                
                # Match the algorithm name to the dictionary score
                score = signature_scores.get(sig_alg_name, 5)  # Default score is 5 if not found
                return score

    except Exception as e:
        print(f"Error occurred: {e}")
        return 0




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

from .models import AnalyzedURL 
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

            # Combine warnings from protocol check
            warnings.extend(protocol_warnings)

            # Check key size and get the key size score
            key_size, key_score, key_warning = check_key_size(cert)
            if key_warning:
                warnings.append(key_warning)
            

            cipher_score=check_signature_algorithm_strength(hostname)
            # Calculate overall score
            overall_score = calculate_overall_score(protocol_score, key_score, cipher_score)

            # Determine the grade
            grade = grade_certificate(overall_score)
            signature_algorithm = cert.signature_algorithm_oid._name
            # Set bar percentages based on the results from the functions
            bar_percentages = {
                'certificate': overall_score ,      #Use the score from overall score
                'protocol_support': protocol_score,  # Use the score from check_protocol_version
                'key_exchange': key_score,            # Use the score from check_key_size
                'cipher_strength': cipher_score,      # Use the score from check_cipher_strength
            }

            # Collect certificate information for rendering
            details = {
                'hostname':hostname,
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
            if request.user.is_authenticated:
                AnalyzedURL.objects.create(user=request.user, url=hostname, grade=grade) 
            

            return render(request, 'analyze.html', details)
        except ssl.SSLError as e:
            return render(request, 'error_page.html', {'message': f"SSL Error: Unable to establish a secure connection to {hostname}"})
        except socket.gaierror:
            return render(request, 'error_page.html', {'message': f"Error: Unable to resolve hostname {hostname}"})
        except socket.error as e:
            return render(request, 'error_page.html', {'message': f"Connection Error: Unable to connect to {hostname}"})
        except Exception as e:
            return render(request, 'error_page.html', {'message': f"Unexpected error analyzing the certificate: {str(e)}"})
        

    return render(request, 'analyze.html')



def analyzed_urls(request):
    if request.user.is_authenticated:
        urls = AnalyzedURL.objects.filter(user=request.user).order_by('-date_analyzed')
        return render(request, 'analyzed_urls.html', {'urls': urls})
    else:
        return redirect('login_view')

def send_email_view(request):
    if request.method == 'POST':
        # Get the form data from POST request
        subject = request.POST['subject']
        message = request.POST['message']
        recipient = 'priya9nshi12@gmail.com'
        
        # Send the email using the send_mail function
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient])
        
        # Return a simple success message
        return HttpResponse('Email sent successfully!')

    # Render the email form HTML page
    return render(request, 'send_email.html')


from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from .models import NotificationSettings 

def notification_alert(request):
    # Check if the user is authenticated
    if not request.user.is_authenticated:
        messages.error(request, "You need to log in to manage notifications.")
        return redirect('login')  # Redirect to login if not authenticated

    # Retrieve or create notification settings for the current user
    notification_settings, created = NotificationSettings.objects.get_or_create(user=request.user)

    if request.method == 'POST' and 'toggle' in request.POST:
        # Toggle the alert status
        notification_settings.alerts_on = not notification_settings.alerts_on
        notification_settings.save()

        if notification_settings.alerts_on:
            # Prepare the email details
            subject = 'ALERT FROM WCD'
            message = f"""Dear {request.user.username},

We hope this message finds you well.

This is a friendly reminder from CertiScan that the SSL certificate for your website has expired. Maintaining an up-to-date SSL certificate is crucial to ensure the security of your site and protect your users’ data.

What does this mean?
With an expired certificate, your website is at risk of losing encryption, leaving it vulnerable to potential security breaches. An expired SSL certificate may also impact your website’s trust and visibility, as modern browsers often flag unsecured websites.

What to do next?
To resolve this, please renew your SSL certificate as soon as possible to ensure your website remains secure and accessible.

If you have any questions or need assistance, feel free to reach out to our support team. We're here to help!

Thank you for trusting CertiScan to monitor your website's SSL security.

Best regards,
The CertiScan Team
"""
            recipient = request.user.email  # Use the user's email

            # Send the email and handle potential errors
            try:
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient])
                messages.success(request, "Alerts have been turned ON and a notification email has been sent.")
            except Exception as e:
                messages.error(request, f"An error occurred while sending the notification email: {e}")
        else:
            messages.success(request, "Alerts have been turned OFF.")

    return render(request, 'notification_alert.html', {'notification_settings': notification_settings})


def contact_view(request):
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        
        # Prepare email
        subject = f"Message from {name}"
        full_message = f"Message from {name} ({email}):\n\n{message}"
        
        # Send email (customize settings.EMAIL_HOST_USER for sender)
        send_mail(subject, full_message, settings.EMAIL_HOST_USER, [settings.EMAIL_RECEIVER])
        messages.success(request, "Thank you! Your message has been sent.")
        return redirect('contact')
        
    return render(request, 'contact.html')

def disclaimer_view(request):
    return render(request, 'disclaimer.html')

# View for the Copyright Page
def copyright_view(request):
    return render(request, 'copyright.html')

# View for the About Us page
def about_view(request):
    return render(request, 'about.html')

def faq_view(request):
    return render(request, 'faq.html')