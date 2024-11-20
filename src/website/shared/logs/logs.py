from collections import OrderedDict
from typing import Any

from django.core.exceptions import ObjectDoesNotExist

from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    DerivationClusterProposalLinkEvent,  # type: ignore
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)

from .utils import get_user_from_context


class SuggestionActivityLog:
    """
    Example of structured log output:
    ```
    {'created_at': datetime.datetime(2024, 11, 16, 1, 59, 1, 968688, tzinfo=datetime.timezone.utc),
     'updates': OrderedDict([(datetime.datetime(2024, 11, 17, 4, 40, 6, 227407, tzinfo=datetime.timezone.utc),
                              [{'action': 'update',
                                'field': 'status',
                                'target': 'accepted',
                                'user': 'alejandrosame'}]),
                             (datetime.datetime(2024, 11, 17, 23, 1, 15, 833363, tzinfo=datetime.timezone.utc),
                              [{'action': 'derivations.remove',
                                'field': 'derivations',
                                'target': {'python3.11-podman-4.7.0': [<NixDerivation: python3.11-podman-4.7.0 m8xhanas>,
                                                                       <NixDerivation: python3.11-podman-4.7.0 24k7kzmh>,
                                                                       <NixDerivation: python3.11-podman-4.7.0 fc091355>,
                                                                       <NixDerivation: python3.11-podman-4.7.0 7hrrv0jf>]},
                                'user': 'alejandrosame'}]),
                             (datetime.datetime(2024, 11, 18, 15, 13, 11, 887550, tzinfo=datetime.timezone.utc),
                              [{'action': 'update',
                                'field': 'status',
                                'target': 'rejected',
                                'user': 'alejandrosame'}]),
                             (datetime.datetime(2024, 11, 18, 15, 13, 43, 773766, tzinfo=datetime.timezone.utc),
                              [{'action': 'update',
                                'field': 'status',
                                'target': 'accepted',
                                'user': 'alejandrosame'}])])}
    ```
    """

    def __init__(self, suggestion: CVEDerivationClusterProposal) -> None:
        self.log = {}
        self.log["updates"] = {}

        # Suggestion creation timestamp
        try:
            self.log["created_at"] = (
                CVEDerivationClusterProposalStatusEvent.objects.get(
                    pgh_obj_id=suggestion.pk, pgh_label="insert"
                ).pgh_created_at
            )
        except ObjectDoesNotExist:
            # In this case, the propsal was inserted before pghistory migrations were
            # deployedj.
            self.log["created_at"] = None

        # Suggestion status updates
        for event in (
            CVEDerivationClusterProposalStatusEvent.objects.prefetch_related(
                "pgh_context",
            )
            .filter(
                pgh_obj_id=suggestion.pk,
            )
            .exclude(
                # Ignore the insertion case
                pgh_label="insert",
            )
        ):
            entry = {}

            entry["user"] = get_user_from_context(event.pgh_context)
            entry["action"] = event.pgh_label
            entry["field"] = "status"
            entry["target"] = event.status

            self.log["updates"] = self._upsert_dict(
                self.log["updates"], event.pgh_created_at, entry
            )

        # Suggestion package updates (additions and removals)
        # First pass groups derivations by name (packages)
        log_first_pass_packages = {}
        query = DerivationClusterProposalLinkEvent.objects.prefetch_related(
            "pgh_context", "derivation"
        ).filter(proposal_id=suggestion.pk)
        if self.log["created_at"] is not None:
            try:
                link_event = DerivationClusterProposalLinkEvent.objects.filter(
                    proposal_id=suggestion.pk
                ).first()
                if link_event is not None:
                    link_creation_timestamp = link_event.pgh_created_at
                    query = query.exclude(
                        # Ignore values at insertion time
                        pgh_created_at=link_creation_timestamp
                    )
            except ObjectDoesNotExist:
                None  # Nothing to filter

        for event in query:
            user = get_user_from_context(event.pgh_context)
            key = (event.pgh_created_at, event.pgh_label, user)
            log_first_pass_packages = self._upsert_dict(
                log_first_pass_packages, key, event.derivation
            )

        # Now we do a second pass over grouped packages to accomodate the timestamp
        # ordered log
        for (
            timestamp,
            action,
            username,
        ), derivations in log_first_pass_packages.items():
            entry = {}

            entry["user"] = username
            entry["action"] = action
            entry["field"] = "derivations"
            entry["target"] = self._derivation_list_as_package_dict(derivations)

            self.log["updates"] = self._upsert_dict(
                self.log["updates"], timestamp, entry
            )

        # Return as OrderedDict sorted by timestamp
        self.log["updates"] = OrderedDict(
            {key: self.log["updates"][key] for key in sorted(self.log["updates"])}
        )

    def _upsert_dict(self, d: dict, key: Any, value: Any) -> dict:
        if key in d:
            d[key].append(value)
        else:
            d[key] = [value]
        return d

    def _derivation_list_as_package_dict(self, derivations: list) -> dict:
        packages = {}

        for derivation in derivations:
            packages = self._upsert_dict(packages, derivation.name, derivation)

        return packages

    def get_structured_log(self) -> dict:
        return self.log
