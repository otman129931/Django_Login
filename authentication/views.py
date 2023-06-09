from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail, EmailMessage
from Login import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from .tokens import generate_token

# Create your views here.
def home(request):
    return render(request,'authentication/index.html')

def signup(request):
    if request.method=='POST':
        username = request.POST.get('username')
        lname = request.POST.get('lname')
        fname = request.POST.get('fname')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        if User.objects.filter(username="username"):
            messages.error(request, "the username already exist ! please try ith an other")
            return redirect('signup')
        if User.objects.filter(email="email"):
            messages.error(request, "the email already registred! ")
            return redirect('signup')
        if pass1 != pass2 :
            messages.error(request, " passwords did not match !")
            return redirect('signup')
        if len(username)> 10 and len(username)<4:
            messages.error(request, "username must be between 4 and 10 charchters !")
        if not username.isalnum():
             messages.error(request, "username must be in alphanumeric  !")
             return redirect('signup')

        myuser =User.objects.create_user(username,email,pass1)
        myuser.first_name=fname
        myuser.last_name=lname
        myuser.is_active=False
        myuser.save()
        messages.success(request, 'Your account has been created successfully \n we have sent you a confirmation email please confirme your Email in ordre to activate you account ')
        
        # Welcome email  
        subject ='Welcome to Otman\'s Blog  Login !!'
        message = 'Hello'+ myuser.first_name+ '!!\n'+'Welcome to the blog \n'+'Thank you for visting my blog \n'+'You will recive an confirmation email \n '+'Please confirme your email to be activate'+'Thank You \n Otan Maarouf'
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently =True)
        
        
           # Email Confirmation
        current_site=get_current_site(request)  
        subject2 ='Confirm your Email @ Otman - Blog !!'
        message2 = render_to_string('EmailConfirmation.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid' : urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)       
        })
        email=EmailMessage(
           subject2,
           message2,
           settings.EMAIL_HOST_USER,
           [myuser,email],
        )
        email.fail_silently=True,
        email.send()
        
       
        
        send_mail(subject, message, from_email, to_list, fail_silently =True)
        
        
        
        
        
        return redirect('signin')
    return render(request,'authentication/signup.html')

def signin(request):
    if request.method=='POST':
        username = request.POST.get('username')
        pass1 = request.POST.get('pass1')
        user=authenticate(username=username, password=pass1)
        if user is not None :
            login(request, user)
            fname=user.first_name
            print("login")
            return render(request, 'authentication/index.html', {'fname':fname})
        else:
            print("not login")
            messages.error(request, 'Bad request')
            return redirect('home')
            
    
    return render(request,'authentication/signin.html')

def signout(request):
    logout(request)
    messages.success(request, "logout successefully")
    return redirect('home')
def activate(request, uid64, token):
    try:
        uid=force_str(urlsafe_base64_decode(uid64))
        myuser=User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser=None
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active=True
        myuser.save()
        login(request, myuser)
        return redirect('home')
    else :
        return render(request, 'ActivationFailed.html')