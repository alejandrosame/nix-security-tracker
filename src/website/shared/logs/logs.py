from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    DerivationClusterProposalLinkEvent,  # type: ignore
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)

from .utils import get_user_from_context


class SuggestionActivityLog:
    def __init__(self, suggestion: CVEDerivationClusterProposal) -> None:
        self.suggestion = suggestion
        self.creation_timestamps = {}
        self.creation_timestamps[CVEDerivationClusterProposalStatusEvent] = (
            CVEDerivationClusterProposalStatusEvent.objects.get(
                pgh_obj_id=self.suggestion.pk, pgh_label="insert"
            ).pgh_created_at
        )
        self.creation_timestamps[DerivationClusterProposalLinkEvent] = (
            CVEDerivationClusterProposalStatusEvent.objects.filter(
                pgh_obj_id=self.suggestion.pk
            )[0].pgh_created_at
        )

    def get_structured_log(self) -> dict:
        log = {}

        log["created_at"] = self.creation_timestamps[
            CVEDerivationClusterProposalStatusEvent
        ]

        log["updates"] = []
        # Suggestion status updates
        for event in (
            CVEDerivationClusterProposalStatusEvent.objects.prefetch_related(
                "pgh_context",
            )
            .filter(
                pgh_obj_id=self.suggestion.pk,
            )
            .exclude(
                # Ignore the insertion case
                pgh_label="insert",
            )
        ):
            update_entry = {}

            update_entry["user"] = get_user_from_context(event.pgh_context)
            update_entry["action"] = f"{event.status}"
            update_entry["object"] = "status"
            update_entry["timestamp"] = event.pgh_created_at

            log["updates"].append(update_entry)

        # Suggestion package updates (additions and removals)
        for event in (
            DerivationClusterProposalLinkEvent.objects.prefetch_related(
                "pgh_context", "derivation"
            )
            .filter(proposal_id=self.suggestion.pk)
            .exclude(
                # Ignore values at insertion time
                pgh_created_at=self.creation_timestamps[
                    DerivationClusterProposalLinkEvent
                ]
            )
        ):
            update_entry = {}

            update_entry["user"] = get_user_from_context(event.pgh_context)
            update_entry["action"] = f"{event.pgh_label}"
            update_entry["object"] = event.derivation
            update_entry["timestamp"] = event.pgh_created_at

            log["updates"].append(update_entry)

        log["updates"] = sorted(log["updates"], key=lambda x: x["timestamp"])

        return log
