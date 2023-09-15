from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import SignInForm, SignUpForm
from .models import Profile
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib import messages
import random
import requests
from django.contrib.auth import get_user_model, login
from realm.models import CustomUser
from .forms import SignUpForm
from .models import Profile
from .forms import VideoUploadForm
from .models import Video
import zipfile
import os
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import Genres, Video
import datetime
from django.urls import reverse
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from .models import  Video, Profile
from .models import Notification
import random
from django.core.mail import send_mail
from .models import CustomUser  # Make sure to import your CustomUser model


def signup(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            User = get_user_model()
            username = form.cleaned_data["username"]
            mobile_number = form.cleaned_data["mobile_number"]
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]

            # Check if the username, email, or mobile number already exist
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username is already taken.")
            elif User.objects.filter(email=email).exists():
                messages.error(request, "Email is already registered.")
            elif User.objects.filter(mobile_number=mobile_number).exists():
                messages.error(request, "Mobile number is already in use.")
            else:
                # Create a new user
                user = User.objects.create_user(
                    username=username, password=password, email=email
                )
                user.mobile_number = (
                    mobile_number  # Save the mobile number in the user model
                )
                user.save()

                # Create a default profile for the user during signup
                profile_name = username
                profile = Profile(
                    user=user, name=profile_name, mobile_number=mobile_number
                )
                profile.save()

                login(request, user)
                subject = "Signup Success"
                context = {"username": username}
                html_message = render_to_string("signup_success_email.html", context)
                plain_message = strip_tags(html_message)
                from_email = "realmdefend@gmail.com"
                to_email = user.email

                send_mail(
                    subject,
                    plain_message,
                    from_email,
                    [to_email],
                    html_message=html_message,
                )
                return redirect("signin")
        else:
            # If the form is not valid, display the error messages
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field.capitalize()}: {error}")
    else:
        form = SignUpForm()

    return render(request, "signup.html", {"form": form})


User = get_user_model()
API_KEY = "2f5f524a-488e-11ee-addf-0200cd936042"   #YOGI API KEY

def signin(request):
    if request.method == "POST":
        if "mobile" in request.POST:
            try:
                user_mobile_number = request.POST["mobile"]
                user = CustomUser.objects.get(mobile_number=user_mobile_number)
                print(user)
                # Generate a random OTP
                otp = str(random.randint(100000, 999999))

                # Send OTP to the user's mobile number
                send_otp_url = f"https://2factor.in/API/V1/{API_KEY}/SMS/{user_mobile_number}/{otp}"

                response = requests.post(send_otp_url)
                if response.status_code == 200:
                    # OTP sent successfully
                    request.session["session_id"] = response.json().get("Details")
                    request.session[
                        "mobile_number"
                    ] = user_mobile_number  # Store mobile number in session
                    return render(
                        request,
                        "otp_verification.html",
                        {"mobile_number": user_mobile_number},
                    )
                    
                # Failed to send OTP
                error_message = response.json().get("Status")
                return render(request, "signin.html", {"error_message": error_message})

            except CustomUser.DoesNotExist:
                error_message = "Invalid or non-existent mobile number."
                return render(request, "signin.html", {"error_message": error_message})

        # Process the username and password login
        username = request.POST["username"]
        password = request.POST["password"]

        if username == "admin" and password == "admin123":
            form = VideoUploadForm(request.POST, request.FILES)
            return redirect(movie_upload)

        if "otp" in request.POST:
            otp = request.POST["otp"]
            session_id = request.session.get("session_id")
            mobile_number = request.session.get("mobile_number")
            # Verify the OTP
            verify_otp_url = (
                f"https://2factor.in/API/V1/{API_KEY}/SMS/VERIFY/{session_id}/{otp}"
            )

            response = requests.get(verify_otp_url)
            if (
                response.status_code == 200
                and response.json().get("Status") == "Success"
            ):
                # OTP verification successful
                user = authenticate(
                    request, username=mobile_number, password=""
                )  # Authenticate with mobile number

                if user is not None:
                    # User is authenticated
                    login(request, user)

                    # Fetch the profiles of the signed-in user
                    profiles = Profile.objects.filter(user=user)

                    if profiles.exists():
                        return render(request, "profile.html", {"profiles": profiles})
                    else:
                        # No profiles found for the user, redirect to profiles page
                        return redirect("profiles")

                else:
                    # Authentication failed
                    error_message = "Invalid username or password."
                    return render(
                        request, "signin.html", {"error_message": error_message}
                    )
            else:
                # OTP verification failed
                error_message = "Invalid OTP."
                return render(request, "signin.html", {"error_message": error_message})

        else:
            # Normal authentication flow
            user = authenticate(request, username=username, password=password)
            if user is not None:
                # User is authenticated
                login(request, user)

                # Fetch the profiles of the signed-in user
                profiles = Profile.objects.filter(user=user)

                if profiles.exists():
                    return render(request, "profile.html", {"profiles": profiles})
                else:
                    # No profiles found for the user, redirect to profiles page
                    return redirect("profiles")

            else:
                # Authentication failed
                error_message = "Invalid username or password."
                return render(request, "signin.html", {"error_message": error_message})

    return render(request, "signin.html")


def otp_verification(request):
    user_mobile_number = request.session.get("mobile_number")
    if request.method == "POST":
        user_entered_otp = ""
        for i in range(1, 7):
            digit = request.POST.get(f"otp{i}")
            if not digit or not digit.isdigit():
                error_message = "Please enter a valid OTP."
                return render(
                    request,
                    "otp_verification.html",
                    {
                        "error_message": error_message,
                        "mobile_number": user_mobile_number,
                    },
                )
            user_entered_otp += digit

        session_id = request.session.get("session_id")
        # Verify the entered OTP
        verify_otp_url = f"https://2factor.in/API/V1/{API_KEY}/SMS/VERIFY/{session_id}/{user_entered_otp}"

        response = requests.post(verify_otp_url)
        if response.status_code == 200:
            json_response = response.json()
            if json_response.get("Status") == "Success":
                # OTP verification successful

                # Get the user associated with the mobile number
                try:
                    user = CustomUser.objects.get(mobile_number=user_mobile_number)
                except CustomUser.DoesNotExist:
                    error_message = "Invalid or non-existent mobile number."
                    return render(
                        request,
                        "otp_verification.html",
                        {
                            "error_message": error_message,
                            "mobile_number": user_mobile_number,
                        },
                    )
                # Fetch the profiles associated with the user
                profiles = Profile.objects.filter(user=user)

                if profiles.exists():
                    return render(request, "profile.html", {"profiles": profiles})
                else:
                    # No profiles found for the user, redirect to profiles page
                    return redirect("profiles")

            else:
                # OTP verification failed
                error_message = json_response.get("Details")
                return render(
                    request,
                    "otp_verification.html",
                    {
                        "error_message": error_message,
                        "mobile_number": user_mobile_number,
                    },
                )

        # Failed to verify OTP
        error_message = "Failed to verify OTP."
        return render(
            request,
            "otp_verification.html",
            {"error_message": error_message, "mobile_number": user_mobile_number},
        )

    return render(
        request, "otp_verification.html", {"mobile_number": user_mobile_number}
    )


def index(request):
    return render(request, "index.html")

def hover_view(request):
    video_source = "static/videos/Kalki.mp4"  # Adjust the path to your video
    return render(request, 'hover.html', {'video_source': video_source})

def hover_player_view(request):
    video_src = request.GET.get('video_src', '')
    return render(request, 'hover_player.html', {'video_src': video_src})

from django.utils import timezone

def movie_upload(request):
    if request.method == "POST":
        form = VideoUploadForm(request.POST, request.FILES)
        if form.is_valid():
            video = form.save(commit=False)

            # Save the video and thumbnail files
            video.video_file = request.FILES["video_file"]
            video.thumbnail = request.FILES["thumbnail"]
            video.save()

            # Unzip the video file if it is a zip file
            if video.video_file.name.endswith(".zip"):
                zip_file_path = video.video_file.path
                target_directory = os.path.dirname(zip_file_path)

                with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
                    zip_ref.extractall(target_directory)

                # Remove the zip file after extraction
                os.remove(zip_file_path)

                # Change the value of video_file to have .m3u8 extension
                new_video_file_name = (
                    os.path.splitext(video.video_file.name)[0] + ".m3u8"
                )
                video.video_file.name = new_video_file_name
                video.save(update_fields=["video_file"])
            # Create a notification record
            notification = Notification(video=video, timestamp=timezone.now())
            notification.save()

            return redirect(
                "movie_upload"
            )  # Redirect to the videos page after successful upload
    else:
        form = VideoUploadForm()
    return render(request, "video_upload.html", {"form": form})


@login_required
def profile(request):
    # Retrieve the logged-in user
    user = request.user
    # Retrieve all profiles associated with the logged-in user
    profiles = Profile.objects.filter(user=user)
    return render(request, "profile.html", {"user": user, "profiles": profiles})


@login_required
def profile(request):
    # Retrieve the logged-in user
    user = request.user
    # Retrieve all profiles associated with the logged-in user
    profiles = Profile.objects.filter(user=user)
    return render(request, "profile.html", {"user": user, "profiles": profiles})





def add_profile(request):
    user = request.user
    profile_count = Profile.objects.filter(user=user).count()

    if profile_count >= 4:
        return redirect("profile")

    if request.method == "POST":
        profile_name = request.POST["profile_name"]
        profile_photo = request.FILES.get(
            "profile_photo"
        )  # Updated field name to 'profile_photo'
        child_profile = request.POST.get("child_profile")
        pin = request.POST.get("pin")  # Get the 'pin' value from the form
        confirm_pin = request.POST.get("cpin")

        if pin == confirm_pin:
            child_profile = True if child_profile == "1" else False

            existing_profile = Profile.objects.filter(
                user=user, name=profile_name
            ).first()
            if existing_profile:
                error_message = "Profile name already exists"
                return render(
                    request,
                    "add_profile.html",
                    {"add_profile_disabled": False, "error_message": error_message},
                )

            profile = Profile(
                user=user,
                name=profile_name,
                photo=profile_photo,
                child_profile=child_profile,
                pin=pin,
            )  # Save 'pin' to the profile
            profile.save()

            profile_count += 1
            if profile_count >= 4:
                add_profile_disabled = True
            else:
                add_profile_disabled = False

            return redirect("profiles")
        else:
            error_message = "PIN and Confirm PIN do not match"
            return render(
                request,
                "add_profile.html",
                {"add_profile_disabled": False, "error_message": error_message},
            )

    return render(request, "add_profile.html", {"add_profile_disabled": False})

def edit_profile(request, profile_id):
    profile = get_object_or_404(Profile, id=profile_id)
    is_first_profile = Profile.objects.filter(user=request.user).first() == profile
    
    if request.method == "POST":
        name = request.POST.get("name")
        profile.name = name
        
        if "profile_picture" in request.FILES:
            profile.photo = request.FILES["profile_picture"]
        
        new_pin = request.POST.get("new_pin")  # New PIN entered during editing
        confirm_pin = request.POST.get("confirm_pin")  # Confirmed PIN
        
        if new_pin:
            if new_pin == confirm_pin:
                profile.pin = new_pin  # Set the new PIN if provided and confirmed
            else:
                # Handle error: Entered PIN and Confirm PIN do not match
                error_message = "Entered PIN and Confirm PIN do not match."
                context = {
                    "profile": profile,
                    "is_first_profile": is_first_profile,
                    "error_message": error_message,
                }
                return render(request, "edit_profile.html", context)
        elif not profile.pin:
            profile.pin = None  # Retain old PIN if not provided during editing
        
        profile.save()
        
        return redirect("profiles")
    
    context = {
        "profile": profile,
        "is_first_profile": is_first_profile,
    }
    return render(request, "edit_profile.html", context)



def profile_detail(request, profile_id):
    profile = get_object_or_404(Profile, id=profile_id)

    if profile.user == request.user:  # User owns the profile
        return render(request, "profile_detail.html", {"profile": profile})

    if profile == Profile.objects.filter(user=request.user).first():  # Default profile
        if request.method == "POST":
            entered_pin = request.POST.get("pin")
            if entered_pin == profile.pin:
                return render(request, "profile_detail.html", {"profile": profile, "can_edit": True})

        return render(request, "pin_verification.html", {"profile": profile})

    return render(request, "profile_detail.html", {"profile": profile})


def delete_profile(request, profile_id):
    profile = get_object_or_404(Profile, id=profile_id)
    profile.delete()
    return redirect("profiles")

def player(request, video_id):
    video = Video.objects.get(id=video_id)
    video_url = video.video_file.url
    print(video_url)
    return render(request, "player.html", {"video_url": video_url})

from django.contrib.sessions.models import Session

@login_required
def home(request):
    categories = Genres.objects.all()
    videos = Video.objects.all()
    profile_name = request.GET.get('profile_name', '')

    # Store the profile name in the session
    request.session['selected_profile_name'] = profile_name
    request.session.save()  # Explicitly save the session

    genre_id = request.GET.get("genre_id")
    if genre_id:
        genre = get_object_or_404(Genres, id=genre_id)
        videos = videos.filter(genres=genre)

    return render(
        request, "category_list.html", {"categories": categories, "videos": videos}
    )





def schedule(request):
    current_time = datetime.datetime.now()
    videos = Video.objects.filter(scheduled_time__lte=current_time)
    return render(request, "scheduled_video.html", {"videos": videos})


def video_list(request, genre_id):
    genre = Genres.objects.get(pk=genre_id)
    videos = Video.objects.filter(genres=genre)
    thumbnails = Video.objects.all()
    context = {"genre": genre, "videos": videos, "thumbnails": thumbnails}
    return render(request, "video_list.html", context)


def search(request):
    videos = Video.objects.all()
    return render(request, "search.html", {"videos": videos})


@login_required
def movies(request):
    videos = Video.objects.all()
    return render(request, "movies.html", {"videos": videos})


def search_kids(request):
    videos = Video.objects.exclude(content_age_rating="18+")
    return render(request, "search1.html", {"videos": videos})


def kid_home(request):
    categories = Genres.objects.all()
    videos = Video.objects.exclude(content_age_rating="18+")
    genre_id = request.GET.get("genre_id")
    if genre_id:
        genre = get_object_or_404(Genres, id=genre_id)
        videos = videos.filter(genres=genre)

    return render(request, "category_list1.html", {"categories": categories, "videos": videos})


def home_kids(request):
    categories = Genres.objects.exclude(
        name__in=["Crime", "Thriller", "Romantic", "Horror"]
    )
    videos = Video.objects.exclude(content_age_rating="18+")

    genre_id = request.GET.get("genre_id")
    if genre_id:
        genre = get_object_or_404(Genres, id=genre_id)
        videos = videos.filter(genres=genre)

    return render(
        request, "category_list1.html", {"categories": categories, "videos": videos}
    )


def video_list1(request, genre_id):
    genre = Genres.objects.get(pk=genre_id)
    videos = Video.objects.filter(genres=genre).exclude(content_age_rating="18+")
    thumbnails = Video.objects.all()
    context = {"genre": genre, "videos": videos, "thumbnails": thumbnails}
    return render(request, "video_list1.html", context)

def movie_details(request, video_id):
    video = get_object_or_404(Video, id=video_id)
    return render(request, "movie.html", {"video": video})


# views.py
def unlock_pin(request):
    if request.method == "POST":
        name = request.POST.get("profilename", "")
        digit1 = request.POST.get("digit1", "")
        digit2 = request.POST.get("digit2", "")
        digit3 = request.POST.get("digit3", "")
        digit4 = request.POST.get("digit4", "")

        submitted_pin = digit1 + digit2 + digit3 + digit4

        # Assuming you have a Profile model with 'pin', 'child_profile', 'name', and 'user' fields
        from .models import Profile

        try:
            # Get the currently logged-in user
            user = request.user

            # Filter profiles for the current user based on the provided name
            profile = Profile.objects.get(user=user, name=name)

            # Check the submitted PIN against the fetched profile's PIN
            if profile.pin == submitted_pin:
                child_profile = profile.child_profile
                print("Child Profile:", child_profile)  # Print the value for debugging

                if child_profile == 0:
                    return redirect("home")
                else:
                    return redirect("home_kids")
            else:
                return render(request, "pin.html", {"error_message": "Invalid PIN"})

        except Profile.DoesNotExist:
            # Profile does not exist
            return render(request, "pin.html", {"error_message": "Invalid Name"})
    else:
        # GET request or other method
        return render(request, "pin.html")




def unlock(request):
    if request.method == "POST":
        name = request.POST.get("profilename", "")
        digit1 = request.POST.get("digit1", "")
        digit2 = request.POST.get("digit2", "")
        digit3 = request.POST.get("digit3", "")
        digit4 = request.POST.get("digit4", "")

        submitted_pin = digit1 + digit2 + digit3 + digit4

        # Assuming you have a Profile model with 'pin', 'child_profile', 'name', and 'user' fields
        from .models import Profile

        try:
            # Get the currently logged-in user
            user = request.user

            # Filter profiles for the current user based on the provided name
            profile = get_object_or_404(Profile, user=user, name=name)

            # Check the submitted PIN against the fetched profile's PIN
            if profile.pin == submitted_pin:
                edit_profile_url = reverse("edit_profile", args=[profile.id])
                return redirect(edit_profile_url)
            else:
                return render(
                    request, "pin_edit.html", {"error_message": "Invalid PIN"}
                )

        except Profile.DoesNotExist:
            # Profile does not exist
            return render(request, "pin_edit.html", {"error_message": "Invalid Name"})
    else:
        # GET request or other method
        return render(request, "pin_edit.html")


@login_required
def toggle_watchlist(request, video_id):
    video = Video.objects.get(pk=video_id)
    user_profile = request.user.userprofile
    
    if video in user_profile.watchlist.all():
        user_profile.watchlist.remove(video)
        added = False
    else:
        user_profile.watchlist.add(video)
        added = True
    
    return JsonResponse({'added': added})


def get_notifications(request):
    latest_notifications = Notification.objects.select_related("video").order_by(
        "-timestamp"
    )[:5]
    notifications_data = [
        {
            "video": notification.video.title,
            "timestamp": notification.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for notification in latest_notifications
    ]
    return JsonResponse(notifications_data, safe=False)












from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages





from django.core.mail import send_mail

def password_reset(request):
    if request.method == "POST":
        email = request.POST.get("email")

        try:
            user = CustomUser.objects.get(email=email)
            otp = str(random.randint(100000, 999999))

            # Send OTP to the user's email (code for sending mail)
            subject = "Password Reset OTP"
            message = f"Your OTP for password reset: {otp}"
            from_email = "your-email@example.com"
            recipient_list = [user.email]

            send_mail(subject, message, from_email, recipient_list)

            request.session["reset_user_id"] = user.id
            request.session["reset_otp"] = otp

            return redirect("verify_otp")

        except CustomUser.DoesNotExist:
            error_message = "Email not found."
            return render(
                request, "forgot_password.html", {"error_message": error_message}
            )

    return render(request, "forgot_password.html")


def verify_otp(request):
    if request.method == "POST":
        entered_otp = request.POST.get("otp")
        expected_otp = request.session.get("reset_otp")

        if expected_otp is not None and entered_otp == expected_otp:
            # Clear OTP from session after successful verification
            del request.session["reset_otp"]
            return redirect("update_password")
            # return render(request, "update_password.html")
        else:
            error_message = "Invalid OTP."
            return render(request, "verify_otp.html", {"error_message": error_message})
    return render(request, "verify_otp.html")


def update_password(request):
    if request.method == "POST":
        new_password = request.POST.get("new_password")
        user_id = request.session.get("reset_user_id")

        try:
            user = CustomUser.objects.get(id=user_id)
            user.set_password(new_password)
            user.save()
            del request.session["reset_user_id"]  # Clear user_id from session
            return render(request, "password_updated.html")
        except CustomUser.DoesNotExist:
            pass

    return render(request, "update_password.html")  # Redirect in case of errors


def password_updated(request):
    return render(request, "password_updated.html")


def shows(request):
    return render(request,'shows.html')



from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from .models import SelectedProfile  # Import your SelectedProfile model

@login_required
def logout_view(request):
    # Check if the user is authenticated before attempting to delete selected profile names
    if request.user.is_authenticated:
        try:
            selected_profile = SelectedProfile.objects.get(user=request.user)
            selected_profile.delete()
        except SelectedProfile.DoesNotExist:
            pass  # Handle the case where the profile doesn't exist or other error

    # Log the user out
    logout(request)

    # Redirect to a logout success page or login page
    return redirect('index')


from .models import SelectedProfile

from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from .models import SelectedProfile  # Import your SelectedProfile model




from django.shortcuts import render, redirect
from .models import SelectedProfile,ProfileWatchlist

from django.shortcuts import redirect
from .models import SelectedProfile

def select_profile(request, profile_name):
    # Get the selected profile for the current user, if it exists
    selected_profile = SelectedProfile.objects.filter(user=request.user).first()

    # If a selected profile exists, update its name
    if selected_profile:
        # Check if the new profile name is different from the current one
        if selected_profile.profile_name != profile_name:
            # Delete the current selected profile
            selected_profile.delete()
            # Create a new selected profile with the new name
            SelectedProfile.objects.create(user=request.user, profile_name=profile_name)
    else:
        # Create a new selected profile if none exists
        SelectedProfile.objects.create(user=request.user, profile_name=profile_name)

    return redirect('home')



from django.shortcuts import get_object_or_404, redirect
from .models import Video, Profile, ProfileWatchlist
from .models import SelectedProfile  # Import the SelectedProfile model

def add_to_watchlist(request, video_id):
    video = get_object_or_404(Video, pk=video_id)
    user = request.user
    
    # Get the selected profile for the current user
    selected_profile = get_object_or_404(SelectedProfile, user=user)
    
    # Get the profile associated with the selected profile name
    profile = get_object_or_404(Profile, user=user, name=selected_profile.profile_name)
    
    # Add the video to the watchlist for the specific profile
    ProfileWatchlist.objects.get_or_create(user=user, profile=profile, video=video)
    
    return redirect('movie_details', video_id=video_id)

from django.db.models import Subquery

def watchlist_display(request):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        # Get the currently logged-in user
        logged_in_user = request.user

        # Subquery to get a list of user_ids and profile_names from SelectedProfile
        selected_profiles_subquery = SelectedProfile.objects.filter(user_id=logged_in_user.id).values('profile_name')

        # Filter the watchlist_items based on profile_name
        watchlist_items = ProfileWatchlist.objects.filter(
            profile_name__in=Subquery(selected_profiles_subquery)
        )

        context = {'watchlist': watchlist_items}
        return render(request, 'watchlist.html', context)
    else:
        # Handle the case when the user is not authenticated (e.g., redirect to login)
        return redirect('login')  # You should adjust this to match your login URL
    
    from django.shortcuts import redirect, get_object_or_404
from .models import ProfileWatchlist

def remove_from_watchlist(request):
    if request.method == 'POST':
        video_id = request.POST.get('video_id')
        
        try:
            item_to_remove = ProfileWatchlist.objects.get(id=video_id)
            
            # You may want to add logic here to verify that the user has permission
            # to remove this item, e.g., check if the item belongs to the user.

            # Remove the item from the watchlist
            item_to_remove.delete()

            # Optionally, you can return a success response or JSON based on your requirements
            return redirect('watchlist_display')

        except ProfileWatchlist.DoesNotExist:
            # Handle the case where the item is not found
            pass

    # Handle other cases or errors
    return redirect('watchlist_display')