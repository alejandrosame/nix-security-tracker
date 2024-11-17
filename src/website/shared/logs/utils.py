from functools import lru_cache
from typing import Any

from django.contrib.auth.models import User

from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    DerivationClusterProposalLinkEvent,  # type: ignore
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)


@lru_cache
def get_username(user_id: int) -> str:
    if user_id is None:
        # TODO: Delete this case once the operations are guarded by
        # auth, or consolidate to signal an inconsistent state to be checked
        # by admins.
        # NOTE(alejandrosame): These operations shouldn't be anonymous,
        # but leaving this case explicitly tagged as anonymous user to avoid
        # confusion with DELETED users.
        return "ANONYMOUS"

    if not User.objects.filter(id=user_id).exists():
        # If user doesn't exist, we assumed it was deleted from the database
        # at their request.
        return "REDACTED"

    return User.objects.get(id=user_id).username


# TODO: add proper type for pgh_context
@lru_cache
def get_user_from_context(context: Any) -> str:
    if context is None:
        # An empty context means that the action took place
        # from a management command by a superadmin.
        return "ADMIN"

    user_id = context.metadata.get("user")
    return get_username(user_id)


def get_suggestion_activity_log(suggestion: CVEDerivationClusterProposal) -> list[str]:
    log = []

    # Suggestion creation, deletion and status updates
    for event in CVEDerivationClusterProposalStatusEvent.objects.prefetch_related(
        "pgh_context",
    ).filter(pgh_obj_id=suggestion.pk):
        user = get_user_from_context(event.pgh_context)
        operation = event.pgh_label
        timestamp = event.pgh_created_at
        log.append(f"@{user} did {operation} status to {event.status} at {timestamp}")

    # Suggestion creation, deletion and package updates (additions and removals)
    count = 0  # TODO: get rid of the count once the abysmal performance is fixed
    for event in DerivationClusterProposalLinkEvent.objects.prefetch_related(
        "pgh_context", "derivation"
    ).filter(proposal_id=suggestion.pk):
        if count == 10:
            break
        user = get_user_from_context(event.pgh_context)
        operation = event.pgh_label
        timestamp = event.pgh_created_at
        log.append(f"@{user} did {operation} package {event.derivation} at {timestamp}")
        count += 1

    return log
