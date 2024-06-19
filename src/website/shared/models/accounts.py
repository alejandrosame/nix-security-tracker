from typing import Any

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    @property
    def is_staff(self) -> bool:
        return True

    @property
    def github_account(self) -> SocialAccount | None:
        # As we only have one social account per user (GitHub), we use the first one.
        return self.socialaccount_set.first()  # type: ignore

    def has_view_permission(self, request: Any, obj: Any) -> Any:
        print("has_view_permission")
        return True

    def has_create_permission(self, request: Any, obj: Any) -> Any:  # type: ignore
        return True

    def has_change_permission(self, request: Any, obj: Any) -> Any:  # type: ignore
        return True

    def has_delete_permission(self, request: Any, obj: Any) -> Any:  # type: ignore
        return True

    def has_perm(self, perm: Any, obj: Any) -> Any:  # type: ignore
        print("here?", perm, self.username)
        # Check if the user has the specified permission
        # You can customize the logic based on your needs
        # if self.is_staff:
        return True
        return super().has_perm(perm, obj)


class UserAdmin(User):
    @property
    def is_staff(self) -> bool:
        print("here2")
        return True


"""

    all_permissions = Permission.objects.all()

    # Assign all permissions to a staff user
    self.user_permissions.set(all_permissions)

# Permissions
from django.contrib.auth.models import Permission

# Get all available permissions
all_permissions = Permission.objects.all()

# Assign all permissions to a staff user
staff_user.user_permissions.set(all_permissions)
"""
