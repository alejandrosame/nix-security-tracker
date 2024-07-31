import re
import typing
from typing import Any

if typing.TYPE_CHECKING:
    from django.db.models.query import ValuesQuerySet

from django import forms
from django.contrib.postgres.aggregates import ArrayAgg
from django.contrib.postgres.search import (
    SearchQuery,
    SearchRank,
)
from django.core.paginator import Page, Paginator
from django.db.models import (
    Count,
    F,
    Max,
    Q,
    Value,
    Window,
)
from django.db.models.functions import RowNumber
from django.db.models.manager import BaseManager
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.utils.functional import cached_property
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import (
    Container,
    CveRecord,
    Description,
    NixDerivation,
    NixDerivationMeta,
    NixpkgsIssue,
)


class HomeView(TemplateView):
    template_name = "home_view.html"


class NixpkgsIssueForm(forms.ModelForm):
    description_text = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = NixpkgsIssue
        fields = ["cve", "derivations", "description_text", "status"]

    def __init__(self, *args: Any, **kwargs: dict[str, Any]) -> None:
        super().__init__(*args, **kwargs)
        self.fields["cve"].choices = []
        self.fields["derivations"].choices = []
        self.fields["description_text"].label = "Description"

    def save(self, *args: Any, **kwargs: dict[str, Any]) -> None:
        issue = NixpkgsIssue.objects.create(
            status=self.cleaned_data["status"],
            description=Description.objects.create(
                value=self.cleaned_data["description_text"]
            ),
        )
        issue.cve.set(CveRecord.objects.filter(id__in=self.cleaned_data["cve"]))
        issue.derivations.set(
            NixDerivation.objects.filter(id__in=self.cleaned_data["derivations"])
        )
        issue.save()


class GroupedPackagePaginator(Paginator):
    @cached_property
    def unique_names(self) -> "ValuesQuerySet[Any, dict[str, Any]]":
        return NixDerivation.objects.values("name").distinct()

    @cached_property
    def count(self) -> int:
        return self.unique_names.count()

    @cached_property
    def ordered_object_list(self) -> "ValuesQuerySet[Any, dict[str, Any]]":
        return self.object_list.values(
            "id", "name", "attribute", "metadata_id", "rank", "rank2"
        ).annotate(
            row_number=Window(
                expression=RowNumber(),
                partition_by=[F("name")],
                order_by=[F("rank").desc(), F("rank2").desc()],
            )
        )

    @cached_property
    def ordered_names(self) -> "ValuesQuerySet[Any, Any]":
        return self.ordered_object_list.filter(row_number=1).values_list(
            "name", flat=True
        )

    def grouped_pkg_page_objects(
        self, sliced_ordered_names: "ValuesQuerySet[Any, Any]"
    ) -> "ValuesQuerySet[Any, dict[str, Any]]":
        return (
            self.ordered_object_list.values("name")
            .filter(name__in=sliced_ordered_names)
            .annotate(
                pkg_count=Count("name"),
                ids=ArrayAgg("id", ordering="id"),
                attributes=ArrayAgg("attribute", ordering="id"),
                metadata_id=Max("metadata_id"),
                max_rank=Max("rank"),
                max_rank2=Max("rank2"),
            )
        )

    def page(self, number: int) -> Page:
        number = self.validate_number(number)
        bottom = (number - 1) * self.per_page
        top = bottom + self.per_page
        if top + self.orphans >= self.count:
            top = self.count
        return super()._get_page(  # type: ignore
            self.grouped_pkg_page_objects(
                sliced_ordered_names=self.ordered_names[bottom:top]
            ),
            number,
            self,
        )


class GroupedCVEPaginator(Paginator):
    # NOTE(alejandrosame): We might actually want to group on cve.cve_id instead of container.id.
    # In that case:
    #   - why would there be more thatn one container for the same cve.cve_id?
    #   - how to properly aggregate, for example, container.title?
    @cached_property
    def unique_cves(self) -> "ValuesQuerySet[Any, dict[str, Any]]":
        return Container.objects.values("id").distinct()

    @cached_property
    def count(self) -> int:
        return self.unique_cves.count()

    @cached_property
    def ordered_object_list(self) -> "ValuesQuerySet[Any, dict[str, Any]]":
        return self.object_list.values(
            "id",
            "title",
            "affected__vendor",
            "affected__product",
            "affected__package_name",
            "affected__repo",
            "affected__cpes__name",
            "cve__cve_id",
            "descriptions__value",
            "rank_sub1",
            "rank_sub2",
            "rank_sub3",
            "rank2",
        ).annotate(
            row_number=Window(
                expression=RowNumber(),
                partition_by=[F("id")],
                order_by=[
                    F("rank_sub1").desc(),
                    F("rank_sub2").desc(),
                    F("rank_sub3").desc(),
                    F("rank2").desc(),
                ],
            )
        )

    @cached_property
    def ordered_ids(self) -> "ValuesQuerySet[Any, Any]":
        return self.ordered_object_list.filter(row_number=1).values_list(
            "id", flat=True
        )

    def grouped_cve_page_objects(
        self, sliced_ordered_ids: "ValuesQuerySet[Any, Any]"
    ) -> "ValuesQuerySet[Any, dict[str, Any]]":
        return (
            self.ordered_object_list.values("id")
            .filter(id__in=sliced_ordered_ids)
            .annotate(
                affected_count=Count("id"),
                cve_id=Max("cve__cve_id"),
                title=Max("title"),
                description=Max("descriptions__value"),
                affected_vendor=Max("affected__vendor"),
                affected_product=Max("affected__product"),
                affected_package_name=Max("affected__package_name"),
                affected_repo=Max("affected__repo"),
                affected_cpes=ArrayAgg(
                    "affected__cpes__name", ordering="affected__cpes__name"
                ),
                max_rank_sub1=Max("rank_sub1"),
                max_rank_sub2=Max("rank_sub2"),
                max_rank_sub3=Max("rank_sub3"),
                max_rank2=Max("rank2"),
            )
        )

    def page(self, number: int) -> Page:
        number = self.validate_number(number)
        bottom = (number - 1) * self.per_page
        top = bottom + self.per_page
        if top + self.orphans >= self.count:
            top = self.count
        return super()._get_page(  # type: ignore
            self.grouped_cve_page_objects(
                sliced_ordered_ids=self.ordered_ids[bottom:top]
            ),
            number,
            self,
        )


def triage_view(request: HttpRequest) -> HttpResponse:
    template_name = "triage_view.html"
    paginate_by = 10
    pages_on_each_side = 2
    pages_on_ends = 1

    form = NixpkgsIssueForm()
    if request.method == "POST":
        form = NixpkgsIssueForm(request.POST)

        if form.is_valid():
            form.save()
            # Redirect to same page
            return HttpResponseRedirect(request.path_info)

    cve_qs = Container.objects.order_by("-cve__cve_id")
    pkg_qs = NixDerivation.objects.order_by("name")

    cve_objects = cve_qs.all()
    pkg_objects = pkg_qs.all()

    # Fetch query parameters
    search_cves = request.GET.get("search_cves")
    search_pkgs = request.GET.get("search_pkgs")

    if search_cves:
        search_query = SearchQuery(search_cves)
        norm_value = Value(1)
        # TODO(alejandrosame): Figure out how to combine SearchVectorFields directly.
        # e.g: rank=SearchRank(F("search_vector")+F("affected__search_vector")+F("affected__cpes__search_vector"), ...),
        cve_objects = cve_qs.annotate(
            rank_sub1=SearchRank(
                F("search_vector"), search_query, normalization=norm_value
            ),
            rank_sub2=SearchRank(
                F("affected__search_vector"), search_query, normalization=norm_value
            ),
            rank_sub3=SearchRank(
                F("affected__cpes__search_vector"),
                search_query,
                normalization=norm_value,
            ),
            rank2=SearchRank(
                F("descriptions__search_vector"), search_query, normalization=norm_value
            ),
        ).filter(
            Q(rank_sub1__gte=0.01)
            | Q(rank_sub2__gte=0.01)
            | Q(rank_sub3__gte=0.01)
            | Q(rank2__gte=0.01)
        )
    else:
        cve_objects = cve_qs.annotate(
            rank_sub1=Value(0.0),
            rank_sub2=Value(0.0),
            rank_sub3=Value(0.0),
            rank2=Value(0.0),
        )

    if search_pkgs:
        # Do a 2-rank search to prevent description contents from penalizing hits on "name" and "attribute"
        search_query = SearchQuery(search_pkgs)
        # Check https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-RANKING
        # for the meaning of normalization values.
        norm_value = Value(1)
        pkg_objects = pkg_qs.annotate(
            rank=SearchRank(F("search_vector"), search_query, normalization=norm_value),
            rank2=SearchRank(
                F("metadata__search_vector"), search_query, normalization=norm_value
            ),
        ).filter(Q(rank__gte=0.01) | Q(rank2__gte=0.01))
    else:
        pkg_objects = pkg_qs.annotate(rank=Value(0.0), rank2=Value(0.0))

    # Paginators
    cve_paginator = GroupedCVEPaginator(cve_objects, paginate_by)
    cve_page_number = request.GET.get("cve_page", 1)
    cve_page_objects = cve_paginator.get_page(cve_page_number)

    pkg_paginator = GroupedPackagePaginator(pkg_objects, paginate_by)
    pkg_page_number = request.GET.get("pkg_page", 1)
    pkg_page_objects = pkg_paginator.get_page(pkg_page_number)

    description_id_list = [object["metadata_id"] for object in pkg_page_objects]
    pkg_descriptions = NixDerivationMeta.objects.values("id", "description").filter(
        id__in=description_id_list
    )
    pkg_descriptions_dict = dict([(desc["id"], desc) for desc in pkg_descriptions])
    sorted_pkg_descriptions = [pkg_descriptions_dict[id] for id in description_id_list]

    context = {
        "cve_list": cve_page_objects,
        "pkg_list": pkg_page_objects,
        "pkg_descriptions": sorted_pkg_descriptions,
        "cve_paginator_range": cve_paginator.get_elided_page_range(  # type: ignore
            cve_page_number, on_each_side=pages_on_each_side, on_ends=pages_on_ends
        ),
        "pkg_paginator_range": pkg_paginator.get_elided_page_range(  # type: ignore
            pkg_page_number, on_each_side=pages_on_each_side, on_ends=pages_on_ends
        ),
        "search_cves": search_cves,
        "search_pkgs": search_pkgs,
        "form": form,
    }

    return render(request, template_name, context)


class NixpkgsIssueView(DetailView):
    template_name = "issue_detail.html"
    model = NixpkgsIssue

    pattern = re.compile(CveRecord._meta.get_field("cve_id").validators[0].regex)

    def get_object(self, queryset: Any = None) -> Any:
        issue = get_object_or_404(self.model, code=self.kwargs.get("code"))
        derivations = issue.derivations.all()  # type: ignore
        for drv in derivations:
            result = self.get_cves_for_derivation(drv)
            drv.known_cves = result

        issue.derivations_with_cves = derivations  # type: ignore

        return issue

    def get_cves_for_derivation(self, drv: Any) -> Any:
        known_vulnerabilities = drv.metadata.known_vulnerabilities
        if not known_vulnerabilities:
            return None
        cves = [s for s in known_vulnerabilities if self.pattern.match(s)]
        existing_cves = Container.objects.filter(cve__cve_id__in=cves)
        if not existing_cves:
            return None
        else:
            return existing_cves


class NixpkgsIssueListView(ListView):
    template_name = "issue_list.html"
    model = NixpkgsIssue

    def get_queryset(self) -> BaseManager[NixpkgsIssue]:
        return NixpkgsIssue.objects.all()
