import argparse
import logging
from typing import Any

from django.core.management.base import BaseCommand
from shared.auth import update_groups_signal

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Update group memberships according to Github memberships."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    def handle(self, *args: str, **kwargs: Any) -> None:  # pyright: ignore reportUnusedVariable
        update_groups_signal.send(sender=None)

        update_groups_signal.send(sender=None)
