import re
from typing import Any, TypedDict

from django.contrib.postgres.aggregates import JSONBAgg
from django.contrib.postgres.search import SearchVector
from django.core.paginator import Paginator
from django.db.models import Count, Func, Q, Value
from django.db.models.manager import BaseManager
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import (
    Container,
    CveRecord,
    NixDerivation,
    NixpkgsIssue,
)


class HomeView(TemplateView):
    template_name = "home_view.html"


class AggregatedNixDerivation(TypedDict):
    id: int
    system: str


aggregate_pkg = Func(
    Value("system"), "system", Value("id"), "id", function="jsonb_build_object"
)


class GroupedNixDerivation(TypedDict):
    name: str
    metadata__description: str
    pkg_count: int
    grouped_pkg_objects: list[AggregatedNixDerivation]


def triage_view(request: HttpRequest) -> HttpResponse:
    template_name = "triage_view.html"
    paginate_by = 10
    pages_on_each_side = 2
    pages_on_ends = 1

    cve_qs = (
        Container.objects.prefetch_related("descriptions", "affected", "cve")
        .exclude(title="")
        .order_by("id", "-date_public")
    )
    pkg_qs = NixDerivation.objects.prefetch_related("metadata").order_by("name")

    cve_objects = cve_qs.all()
    pkg_objects = pkg_qs.all()

    # Fetch query parameters
    search_cves = request.GET.get("search_cves")
    search_pkgs = request.GET.get("search_pkgs")

    if search_cves:
        cve_objects = cve_qs.filter(
            Q(search_vector=search_cves)
            | Q(descriptions__search_vector=search_cves)
            | Q(affected__search_vector=search_cves)
            | Q(affected__cpes__search_vector=search_cves)
        ).distinct("id")

    if search_pkgs:
        pkg_objects = pkg_qs.annotate(
            search=SearchVector(
                "attribute",
                "name",
                "system",
                "metadata__name",
                "metadata__description",
            )
        ).filter(search=search_pkgs)

    # Paginators
    cve_paginator = Paginator(cve_objects, paginate_by)
    cve_page_number = request.GET.get("cve_page", 1)
    cve_page_objects = cve_paginator.get_page(cve_page_number)

    # NOTE(alejandrosame): Alternatively, don't group here but use group in template.
    # This will require using a custom paginator that guarantees that derivations with the same name
    # are returned by the same page (otherwise, some could have been left at PAGE-1 or PAGE+1)
    # NOTE(alejandrosame): I wanted to use the type
    #   ValuesQuerySet[NixDerivation, GroupedNixDerivation]
    # instead of
    #   ValuesQuerySet[NixDerivation, dict[str, Any]].
    # So this type check will need to be done with tests.
    grouped_pkg_objects = pkg_objects.values("name", "metadata__description").annotate(
        pkg_count=Count("name"),
        grouped_pkg_objects=JSONBAgg(aggregate_pkg, ordering="id"),
    )

    pkg_paginator = Paginator(grouped_pkg_objects, paginate_by)
    pkg_page_number = request.GET.get("pkg_page", 1)
    pkg_page_objects = pkg_paginator.get_page(pkg_page_number)

    context = {
        "cve_list": cve_page_objects,
        "pkg_list": pkg_page_objects,
        "cve_paginator_range": cve_paginator.get_elided_page_range(  # type: ignore
            cve_page_number, on_each_side=pages_on_each_side, on_ends=pages_on_ends
        ),
        "pkg_paginator_range": pkg_paginator.get_elided_page_range(  # type: ignore
            pkg_page_number, on_each_side=pages_on_each_side, on_ends=pages_on_ends
        ),
        "cve_paginator_ellipsis": cve_paginator.ELLIPSIS,  # type: ignore
        "pkg_paginator_ellipsis": pkg_paginator.ELLIPSIS,  # type: ignore
        "search_cves": search_cves,
        "search_pkgs": search_pkgs,
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
