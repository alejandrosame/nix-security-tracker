from django.urls import path, re_path
from django.views.generic.base import RedirectView

from webview.views import (
    HomeView,
    NixderivationPerChannelView,
    NixpkgsIssueListView,
    NixpkgsIssueView,
)

app_name = "webview"


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("issues/", NixpkgsIssueListView.as_view(), name="issue_list"),
    re_path(
        r"^issues/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})$",
        NixpkgsIssueView.as_view(),
        name="issue_detail",
    ),
    re_path(
        "^derivations/(?P<channel>nixos-.*)$",
        NixderivationPerChannelView.as_view(),
        name="drv_per_channel",
    ),
    path(
        "derivations/",
        RedirectView.as_view(url="nixos-unstable", permanent=True),
        name="drv",
    ),
]
