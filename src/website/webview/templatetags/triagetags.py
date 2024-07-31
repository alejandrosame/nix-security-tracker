from collections.abc import Iterable
from typing import Any

from django import template

register = template.Library()


@register.filter
def clean_nones(input: Iterable[Any]) -> Iterable[Any]:
    return filter(lambda e: e is not None, input)


@register.filter
def default_to_na(input: Any) -> Any:
    if input == "n/a" or input == "" or input is None:
        return "N/A"
    return input
