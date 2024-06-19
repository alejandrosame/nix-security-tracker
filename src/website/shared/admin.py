# Register your models here.


from typing import Any

from django.apps import apps
from django.contrib import admin
from django.contrib.admin import AdminSite


class CustomAdminSite(AdminSite):
    def has_permission(self, request: Any) -> Any:  # type: ignore
        if request.user.is_authenticated:
            if request.user.is_staff:
                return True
            return super().has_permission(request)  # type: ignore
        return False


class CustomModelAdmin(admin.ModelAdmin):
    def has_view_permission(self, request: Any) -> Any:  # type: ignore
        print("has_view_permission")
        return True

    def has_add_permission(self, request: Any) -> Any:
        return True

    def has_change_permission(self, request: Any) -> Any:
        return True

    def has_delete_permission(self, request: Any) -> Any:
        return True


custom_admin_site = CustomAdminSite()

models = apps.get_models()
for model in models:
    custom_admin_site.register(model, CustomModelAdmin)


# Unregister the provided model admin
# admin.site.unregister(DefaultUser)
# admin.site.register(User)

# @admin.register(User)
# class CustomUserAdmin(DefaultUserAdmin):
#    def has_view_permission(self, request: Any, obj=None): return True
#    def has_create_permission(self, request: Any, obj=None): return True
#    def has_change_permission(self, request: Any, obj=None): return True
#    def has_delete_permission(self, request: Any, obj=None): return True
