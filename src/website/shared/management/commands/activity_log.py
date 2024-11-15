import argparse
import logging
from typing import Any

import pghistory
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from shared.models import (
    NixpkgsIssue,
    NixpkgsIssueCveThroughProxyEvent,
    NixpkgsIssueDerivationsThroughProxyEvent,
    NixpkgsIssueStatusEvent,
)

logger = logging.getLogger(__name__)


def print_nixpkgs_activity_log(issue_code, print_from_unified_event=False):
    issue = NixpkgsIssue.objects.get(code=issue_code)

    print(f"Activity log for issue {issue_code}:")
    for event in NixpkgsIssueStatusEvent.objects.prefetch_related("pgh_context").filter(
        pgh_obj=issue
    ):
        # .values('pgh_context', 'pgh_context_id', 'pgh_created_at', 'pgh_id', 'pgh_label', 'pgh_obj', 'pgh_obj_id', 'status'):
        user_id = event.pgh_context.metadata["user"]
        user = User.objects.get(id=user_id)
        operation = event.pgh_label
        timestamp = (
            event.pgh_created_at
        )  # Probably only needed to order the operations but not display it
        print(f"\t@{user} did {operation} at {timestamp}")

    # CVE
    for event in NixpkgsIssueCveThroughProxyEvent.objects.prefetch_related(
        "cverecord", "pgh_context"
    ).filter(nixpkgsissue_id=issue.id):
        # .values('pgh_context', 'pgh_context_id', 'pgh_created_at', 'pgh_id', 'pgh_label', 'pgh_obj', 'pgh_obj_id', 'status'):
        user_id = event.pgh_context.metadata["user"]
        user = User.objects.get(id=user_id)
        operation = event.pgh_label
        target = event.cverecord
        timestamp = (
            event.pgh_created_at
        )  # Probably only needed to order the operations but not display it
        print(f"\t@{user} did {operation} {target} at {timestamp}")

    # Derivations
    for event in NixpkgsIssueDerivationsThroughProxyEvent.objects.prefetch_related(
        "nixderivation", "pgh_context"
    ).filter(nixpkgsissue_id=issue.id):
        # .values('pgh_context', 'pgh_context_id', 'pgh_created_at', 'pgh_id', 'pgh_label', 'pgh_obj', 'pgh_obj_id', 'status'):
        user_id = event.pgh_context.metadata["user"]
        user = User.objects.get(id=user_id)
        operation = event.pgh_label
        target = event.nixderivation
        timestamp = (
            event.pgh_created_at
        )  # Probably only needed to order the operations but not display it
        print(f"\t@{user} did {operation} {target} at {timestamp}")

    if print_from_unified_event:
        print()
        print()
        print(f"[From unified mode] Activity log for issue {issue_code}:")
        for event in pghistory.models.Events.objects.all():
            print("pgh_slug:", event.pgh_slug)
            print("pgh_model:", event.pgh_model)
            print("pgh_id:", event.pgh_id)
            print("pgh_label:", event.pgh_label)
            print("pgh_created_at:", event.pgh_created_at)
            print("pgh_diff:", event.pgh_diff)
            print("pgh_context_id:", event.pgh_context_id)
            print("pgh_context:", event.pgh_context)
            print("pgh_obj_model:", event.pgh_obj_model)
            print("pgh_obj_id:", event.pgh_obj_id)

            print()


class Command(BaseCommand):
    help = "Activity log examples."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    def handle(self, *args: str, **kwargs: Any) -> None:  # pyright: ignore reportUnusedVariable
        """
        print(NixpkgsIssueAggregatedLog.objects.count())
        print(NixpkgsIssueAggregatedLog.objects.all()[0:10])
        """

        issue_code = "NIXPKGS-2024-0001"
        issue = NixpkgsIssue.objects.get(code=issue_code)

        print_nixpkgs_activity_log(issue_code, print_from_unified_event=False)
