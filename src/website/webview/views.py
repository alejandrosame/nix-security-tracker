import re
from typing import Any, TypedDict

from django import forms
from django.contrib.postgres.aggregates import JSONBAgg
from django.contrib.postgres.search import (
    SearchQuery,
    SearchRank,
    SearchVector,
)
from django.core.paginator import Paginator
from django.db.models import Count, Func, Max, Q, Value
from django.db.models.manager import BaseManager
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import (
    Container,
    CveRecord,
    Description,
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
        # TODO: improve this message
        # Do a 2-rank search to prevent description contents from penalizing hits on "name" and "attribute"
        search_vector = SearchVector("name") + SearchVector("attribute")
        secondary_search_vector = SearchVector("metadata__description")
        search_query = SearchQuery(search_pkgs)
        # Check https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-RANKING
        # for the meaning of normalization values.
        norm_value = Value(1)
        pkg_objects = (
            pkg_qs.annotate(
                rank=SearchRank(search_vector, search_query, normalization=norm_value)
            )
            .annotate(
                rank2=SearchRank(
                    secondary_search_vector, search_query, normalization=norm_value
                )
            )
            .filter(Q(rank__gte=0.01) | Q(rank2__gte=0.01))
        )
    else:
        pkg_objects = pkg_qs.annotate(rank=Value(0.0)).annotate(rank2=Value(0.0))

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
    grouped_pkg_objects = (
        pkg_objects.values("name", "metadata__description")
        .annotate(
            pkg_count=Count("name"),
            max_rank=Max("rank"),
            max_rank2=Max("rank2"),
            grouped_pkg_objects=JSONBAgg(aggregate_pkg, ordering="id"),
        )
        .order_by("-max_rank", "-max_rank2", "name")
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
