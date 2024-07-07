# Register your models here.

from collections.abc import Callable
from typing import Any

from django import forms
from django.apps import apps
from django.contrib import admin
from django.db import models
from django.db.models import CharField, ForeignKey, ManyToManyField, TextField
from shared.auth import isadmin, ismaintainer
from shared.models import (
    Container,
    NixDerivation,
    NixDerivationMeta,
    NixpkgsIssue,
)
from tracker.admin import custom_admin_site

admin_site = custom_admin_site


# Mixins
class CustomAdminPermissionsMixin:
    def has_view_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return isadmin(request)

    def has_change_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return isadmin(request)

    def has_add_permission(self, request: Any) -> bool:
        return isadmin(request)

    def has_delete_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return isadmin(request)

    def has_module_permission(self, request: Any) -> bool:
        return isadmin(request)


class MaintainerPermissionsMixin(CustomAdminPermissionsMixin):
    def has_view_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return isadmin(request) or ismaintainer(request)

    def has_change_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        print("here change")
        return isadmin(request) or ismaintainer(request)

    def has_add_permission(self, request: Any) -> bool:
        print("here add")
        return isadmin(request) or ismaintainer(request)

    def has_delete_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return isadmin(request) or ismaintainer(request)

    def has_module_permission(self, request: Any) -> bool:
        return isadmin(request) or ismaintainer(request)


class ReadOnlyMixin:
    """
    Make all fields read-only.
    No idea why it has to be done this way, but it works.
    """

    model: type[models.Model]

    def get_fields(self, request: object, obj: models.Model | None = None) -> list[str]:
        return [field.name for field in self.model._meta.fields]

    def get_readonly_fields(
        self, request: object, obj: models.Model | None = None
    ) -> list[str]:
        # existing objects are read-only
        if obj:
            return self.get_fields(request, obj)
        # all fields, except automatic ones, are writeable on creation (for debugging)
        else:
            return [
                field.name
                for field in self.model._meta.fields
                if (
                    isinstance(field, models.AutoField)
                    or (isinstance(field, models.DateTimeField) and field.auto_now_add)
                )
            ]


class AutocompleteMixin:
    """
    Make all relation fields autocomplete fields to avoid hanging on large relations.
    This requires setting search fields on the related models.
    """

    def __init__(self, model: type[models.Model], admin_site: Any) -> None:
        super().__init__(model, admin_site)  # type: ignore
        self.set_autocomplete_fields(model)

    def set_autocomplete_fields(self, model: type[models.Model]) -> None:
        for field in model._meta.get_fields():
            if isinstance(field, ForeignKey | ManyToManyField):
                # Update autocomplete_fields
                self.autocomplete_fields = list(
                    getattr(self, "autocomplete_fields", [])
                )
                if field.name not in self.autocomplete_fields:
                    self.autocomplete_fields.append(field.name)

                # Add search_fields to the referenced models
                related_model = field.remote_field.model
                related_admin = admin_site._registry.get(related_model)
                # if not related_admin:
                # related_admin = self.create_related_admin(related_model)
                if related_admin:
                    self.set_search_fields(related_model, related_admin)

    def set_search_fields(
        self,
        model: type[models.Model],
        admin_class: type[admin.ModelAdmin] | admin.ModelAdmin,
    ) -> None:
        search_fields = [
            field.name
            for field in model._meta.get_fields()
            if isinstance(field, CharField | TextField)
        ]
        if search_fields == []:
            search_fields = ["__str__"]

        admin_class.search_fields = list(getattr(admin_class, "search_fields", []))
        if not admin_class.search_fields:
            admin_class.search_fields = search_fields


# Register all models from the 'shared' app
shared_app_config = apps.get_app_config("shared")
shared_models = shared_app_config.get_models()
for model in shared_models:
    modeladmin = type(
        f"{model.__name__}Admin",
        (
            # ReadOnlyMixin,
            # AutocompleteMixin,
            CustomAdminPermissionsMixin,
            admin.ModelAdmin,
        ),
        {},
    )

    admin_site.register(model, modeladmin)


def override(model_class: type[Any]) -> Callable[[type[Any]], type[Any]]:
    def decorator(admin_class: type[Any]) -> type[Any]:
        if admin_site.is_registered(model_class):
            admin_site.unregister(model_class)
        admin_site.register(model_class, admin_class)
        return model_class

    return decorator


@override(NixDerivationMeta)
class NixDerivationMetaAdmin(
    # AutocompleteMixin,
    MaintainerPermissionsMixin,
    admin.ModelAdmin,
):
    # search_fields = ["known_vulnerabilities"]
    pass

    '''
    def get_queryset(self, request):
        """ Limit elements shown for pkg maintainer """
        queryset = NixDerivationMeta.objects.all()

        if not isadmin(request) and ismaintainer(request):
            queryset = (
                NixDerivationMeta.objects.prefetch_related('maintainers')
                    .filter(maintainers__github=request.user.username)
            )

        return queryset
    '''


# @admin.register(Container, site=admin_site)
@override(Container)
class ContainerAdmin(
    # AutocompleteMixin,
    CustomAdminPermissionsMixin,
    admin.ModelAdmin,
):
    # search_fields = ["title"]

    def get_search_results(
        self, request: Any, queryset: Any, search_term: str
    ) -> tuple[Any, bool]:
        queryset, use_distinct = super().get_search_results(
            request, queryset, search_term
        )

        if search_term:
            # allow search in nested CVE objectss
            queryset |= self.model.objects.filter(cve__cve_id__icontains=search_term)
            use_distinct = True

        return queryset, use_distinct


def nixpkgsissueform_factory(request: Any) -> type[forms.ModelForm]:
    """Inject request through a form factory function"""

    class NixpkgsIssueForm(forms.ModelForm):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Init actions based on request user"""

            self.request = request
            super().__init__(*args, **kwargs)

        class Meta:
            model = NixpkgsIssue
            fields = "__all__"

        def clean(self) -> dict[str, Any]:
            cleaned_data = super().clean()
            derivations = cleaned_data.get("derivations")
            if derivations:
                for derivation in derivations:
                    is_pkg_maintainer = derivation.metadata.maintainers.filter(
                        github=request.user.username
                    ).exists()
                    if not is_pkg_maintainer:
                        self.add_error(
                            "derivations",
                            "Cannot add issues that relate to derivations you do not maintain.",
                        )

            return cleaned_data

    return NixpkgsIssueForm


# @admin.register(NixpkgsIssue, site=admin_site)
@override(Container)
class NixpkgsIssueAdmin(MaintainerPermissionsMixin, admin.ModelAdmin):
    # TODO: check permission functions
    def has_view_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return super().has_change_permission(request, obj)

    def has_change_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return super().has_change_permission(request, obj)

    def has_add_permission(self, request: Any) -> bool:
        return super().has_add_permission(request)

    def has_delete_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return super().has_delete_permission(request, obj)

    def has_module_permission(self, request: Any) -> bool:
        return super().has_module_permission(request)

    def get_form(
        self, request: Any, obj: Any = None, **kwargs: Any
    ) -> type[forms.ModelForm]:
        def _isadmin(request: Any) -> bool:
            from django.conf import settings

            if not request.user.is_authenticated:
                return False

            return (
                request.user.is_staff
                or request.user.groups.filter(
                    name=settings.GROUP_SECURITY_TEAM
                ).exists()
            )

        if _isadmin(request):
            return super().get_form(request, obj, **kwargs)
        else:
            return nixpkgsissueform_factory(request)

    '''
    def get_queryset(self, request):
        """ Limit elements shown for pkg maintainer """
        queryset = NixpkgsIssue.objects.all()

        if not isadmin(request) and ismaintainer(request):
            queryset = (
                NixpkgsIssue.objects.prefetch_related('derivations__metadata__maintainers')
                    .filter(derivations__metadata__maintainers__github=request.user.username)
            )

        return queryset
    '''


@override(NixDerivation)
class NixDerivationAdmin(
    # AutocompleteMixin,
    MaintainerPermissionsMixin,
    admin.ModelAdmin,
):
    # search_fields = ["name"]
    pass
    '''
    def get_queryset(self, request):
        """ Limit elements shown for pkg maintainer """
        queryset = NixDerivation.objects.all()

        if not isadmin(request) and ismaintainer(request):
            print("yo")
            queryset = (
                NixDerivation.objects.prefetch_related('metadata__maintainers')
                    .filter(metadata__maintainers__github=request.user.username)
            )

        return queryset
    '''


# @override(NixDerivation)
# class ContainerAdmin(
#    AutocompleteMixin, MaintainerPermissionsMixin, admin.ModelAdmin
# ):
#    search_fields = ["name"]
