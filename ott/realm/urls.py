# urls.py
from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings
from django.views.generic import TemplateView
from .views import player, movie_upload, movie_details
urlpatterns = [
    path("", views.index, name="index"),
    path("signin/", views.signin, name="signin"),
    path("profiles/", views.profile, name="profiles"),
    path("add_profile/", views.add_profile, name="add_profile"),
    path("profiles/<int:profile_id>/edit/", views.edit_profile, name="edit_profile"),
    path(
        "profiles/<int:profile_id>/delete/", views.delete_profile, name="delete_profile"
    ),
    path("otp-verification/", views.otp_verification, name="otp_verification"),
    path("movie_upload", movie_upload, name="movie_upload"),
    path("signup", views.signup, name="signup"),
    path('home', views.home, name='home'),
    path("videos/<int:genre_id>/", views.video_list, name="video_list"),
    path("search/", views.search, name="search"),
    path("movies/", views.movies, name="movies"),
    path("search_kids/", views.search_kids, name="search_kids"),
    path("schedule", views.schedule, name="schedule"),
    path('home_kids', views.home_kids, name='home_kids'),
    path("video_list1/<int:genre_id>/", views.video_list1, name="video_list1"),
    path("unlock-pin", views.unlock_pin, name="unlock_pin"),
    path("logout/", views.logout_view, name="logout"),
    path("movie/<int:video_id>/", movie_details, name="movie_details"),
    path("unlock", views.unlock, name="unlock"),
    path("movie/<int:video_id>/", views.movie_details, name="movie_details"),
    path("player/<int:video_id>/", views.player, name="player"),
    path("get_notifications/", views.get_notifications, name="get_notifications"),
    path('add_to_watchlist/<int:video_id>/', views.add_to_watchlist, name='add_to_watchlist'),
    path("watchlist_display/", views.watchlist_display, name="watchlist_display"),
    path('password_reset/', views.password_reset, name='password_reset'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('update_password/', views.update_password, name='update_password'),
    path('password_updated/', views.password_updated, name='password_updated'),
    path('hover/', views.hover_view, name='hover'),
    path('hover_player/', views.hover_player_view, name='hover_player'),
    path('profiles/<int:profile_id>/', views.profile_detail, name='profile_detail'),
    path('shows',views.shows,name='shows'),
    path('select_profile/<str:profile_name>/', views.select_profile, name='select_profile'),
    path('remove_from_watchlist/', views.remove_from_watchlist, name='remove_from_watchlist'),


] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)