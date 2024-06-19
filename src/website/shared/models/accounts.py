from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    @property
    def github_account(self) -> SocialAccount | None:
        # As we only have one social account per user (GitHub), we use the first one.
        return self.socialaccount_set.first()  # type: ignore
