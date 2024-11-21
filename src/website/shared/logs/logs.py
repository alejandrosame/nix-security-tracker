from collections import OrderedDict
from typing import Any

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
    {
     'updates': OrderedDict([(datetime.datetime(2024, 11, 17, 4, 40, 6, 227407, tzinfo=datetime.timezone.utc),
                              [{'action': 'update',
                                'field': 'status',
                                'target': 'accepted',
                                'user': 'alejandrosame'}]),
                             (datetime.datetime(2024, 11, 20, 14, 10, 23, 777950, tzinfo=datetime.timezone.utc),
                              [{'action': 'derivations.remove',
                                'field': 'derivations',
                                'target': {'buildah-1.32.3': [<NixDerivation: buildah-1.32.3 j912x2s0>,
                                                              <NixDerivation: buildah-1.32.3 vnvajc9s>,
                                                              <NixDerivation: buildah-1.32.3 7pm5dhsi>,
                                                              <NixDerivation: buildah-1.32.3 470a9nq3>],
                                           'python3.11-podman-4.7.0': [<NixDerivation: python3.11-podman-4.7.0 m8xhanas>,
                                                                       <NixDerivation: python3.11-podman-4.7.0 24k7kzmh>,
                                                                       <NixDerivation: python3.11-podman-4.7.0 fc091355>,
                                                                       <NixDerivation: python3.11-podman-4.7.0 7hrrv0jf>]},
                                'user': 'alejandrosame'}]),
                             (datetime.datetime(2024, 11, 20, 14, 18, 8, 90127, tzinfo=datetime.timezone.utc),
                              [{'action': 'update',
                                'field': 'status',
                                'target': 'rejected',
                                'user': 'alejandrosame'}]),
                             (datetime.datetime(2024, 11, 20, 14, 18, 21, 215105, tzinfo=datetime.timezone.utc),
                              [{'action': 'update',
                                'field': 'status',
                                'target': 'accepted',
                                'user': 'alejandrosame'}])])}
    ```
    """

    def __init__(self, suggestion: CVEDerivationClusterProposal) -> None:
        self.log = {}
        self.log["updates"] = {}

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

        # NOTE(alejandrosame): The following insertion timestamp logic can be removed once
        # there's a guarantee that mixin times and pghistory times are in sync with the required
        # transactionality. If that conditioin is met, instead of filtering by `insertion_timestamp`,
        # it will suffice to filter by `suggestion.created_at`.
        insertion_event = (
            DerivationClusterProposalLinkEvent.objects.filter(proposal_id=suggestion.pk)
            .order_by("pgh_created_at")
            .first()
        )

        insertion_timestamp = None
        if insertion_event:
            insertion_timestamp = insertion_event.pgh_created_at

        # First pass groups derivations by name (packages)
        log_first_pass_packages = {}
        for event in (
            DerivationClusterProposalLinkEvent.objects.prefetch_related(
                "pgh_context", "derivation"
            )
            .filter(proposal_id=suggestion.pk)
            .exclude(
                # Ignore values at insertion time
                pgh_created_at=insertion_timestamp
            )
        ):
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
