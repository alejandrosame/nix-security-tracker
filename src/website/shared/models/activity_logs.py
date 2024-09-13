from typing import Any

import pghistory
from django.contrib.auth.models import User
from django.db import connection, models
from django.db.models import (
    BigIntegerField,
    ExpressionWrapper,
    F,
    Value,
)
from django.db.models.query import RawQuerySet
from pghistory.models import Context

from .cve import NixpkgsIssue


# `cve` and `derivations` fields have to be tracked with via their `through` models
class NixpkgsIssueLog(
    pghistory.create_event_model(
        NixpkgsIssue,
        model_name="NixpkgsIssueLog",
        fields=["status"],
    )
):
    pass


# Tracking many-to-many cve relationship of NixpkgsIssue
class NixpkgsIssueCveProxy(NixpkgsIssue.cve.through):
    class Meta:
        proxy = True


class NixpkgsIssueCveLog(
    pghistory.create_event_model(
        NixpkgsIssueCveProxy,
        pghistory.InsertEvent("cve.add"),
        pghistory.DeleteEvent("cve.remove"),
        model_name="NixpkgsIssueCveLog",
    )
):
    pass


# Tracking many-to-many derivations relationship of NixpkgsIssue
class NixpkgsIssueDerivationProxy(NixpkgsIssue.derivations.through):
    class Meta:
        proxy = True


class NixpkgsIssueDerivationLog(
    pghistory.create_event_model(
        NixpkgsIssueDerivationProxy,
        pghistory.InsertEvent("derivations.add"),
        pghistory.DeleteEvent("derivations.remove"),
        model_name="NixpkgsIssueDerivationLog",
    )
):
    pass


# The NixpkgsIssue aggregated activity log model maps to a RAW SQL query, which originally was a Postgresql VIEW table.
# Django doesn't support multimodel proxy models, which would make the equivalent of database view table via ORM.
# It's not possible to construct the whole query using Django ORM, because there are limitations with the
# operations available after doing UNION of tables/subqueries
# (https://docs.djangoproject.com/en/4.2/ref/models/querysets/#union)
# Therefore, all the subqueries necessary for the Postgresql CTE expression are done via Django ORM
# in the function `get_issue_activity_log_queryset` which gets reused in the RAW SQL query expressed in then
# `Meta.db_table` field.
class NixpkgsIssueAggregatedLogQueryManager(models.Manager):  # type: ignore
    def _get_issue_activity_log_queryset(self) -> Any:
        issuelogcontext = (
            NixpkgsIssueLog.objects.prefetch_related("pgh_obj", "pgh_context")
            .annotate(
                context_id=F("pgh_context__id"),
                timestamp=F("pgh_context__created_at"),
                user_id=F("pgh_context__metadata__user"),
                table=Value("shared_nixpkgsissue"),
                entry_id=F("pgh_obj_id"),
                field=Value("status"),
                action=F("pgh_label"),
                value=F("status"),
                value_id=ExpressionWrapper(Value(None), output_field=BigIntegerField()),
            )
            .values(
                "context_id",
                "timestamp",
                "user_id",
                "table",
                "entry_id",
                "field",
                "action",
                "value",
                "value_id",
            )
        )

        icvelogcontext = (
            NixpkgsIssueCveLog.objects.prefetch_related(
                "pgh_obj", "pgh_context", "cverecord"
            )
            .annotate(
                context_id=F("pgh_context__id"),
                timestamp=F("pgh_context__created_at"),
                user_id=F("pgh_context__metadata__user"),
                table=Value("shared_nixpkgsissue"),
                entry_id=F("pgh_obj__nixpkgsissue_id"),
                field=Value("cve"),
                action=F("pgh_label"),
                value=F("cverecord__cve_id"),
                value_id=F("cverecord_id"),
            )
            .values(
                "context_id",
                "timestamp",
                "user_id",
                "table",
                "entry_id",
                "field",
                "action",
                "value",
                "value_id",
            )
        )

        idrvlogcontext = (
            NixpkgsIssueDerivationLog.objects.prefetch_related(
                "pgh_obj", "pgh_context", "nixderivation"
            )
            .annotate(
                context_id=F("pgh_context__id"),
                timestamp=F("pgh_context__created_at"),
                user_id=F("pgh_context__metadata__user"),
                table=Value("shared_nixpkgsissue"),
                entry_id=F("pgh_obj__nixpkgsissue_id"),
                field=Value("derivation"),
                action=F("pgh_label"),
                value=F("nixderivation__attribute"),
                value_id=F("nixderivation_id"),
            )
            .values(
                "context_id",
                "timestamp",
                "user_id",
                "table",
                "entry_id",
                "field",
                "action",
                "value",
                "value_id",
            )
        )

        issue_activity_log = issuelogcontext.union(icvelogcontext, idrvlogcontext)

        return issue_activity_log

    def get_queryset(self) -> Any:
        qs = self._get_issue_activity_log_queryset()
        compiled_query = qs.query.get_compiler(using=qs.db).as_sql()
        query_string = compiled_query[0]
        params = compiled_query[1]

        raw_query = f"""
            WITH issue_activity_log AS ({query_string}),
            issue_activity_log_grouped AS (
                SELECT context_id,
                    timestamp,
                    user_id,
                    l.table,
                    entry_id,
                    jsonb_agg(jsonb_build_object(
                            'field',    field,
                            'action',   action,
                            'value',    value,
                            'value_id', value_id
                    )) AS changes
                FROM issue_activity_log l
                GROUP BY context_id, timestamp, user_id, l.table, entry_id
                ORDER BY timestamp
            )
            SELECT row_number() OVER () as id, ialg.* FROM issue_activity_log_grouped ialg;
        """

        return RawQuerySet(raw_query, params=params, model=NixpkgsIssueAggregatedLog)

    def count(self) -> Any:
        qs = self._get_issue_activity_log_queryset()
        compiled_query = qs.query.get_compiler(using=qs.db).as_sql()
        query_string = compiled_query[0]
        params = compiled_query[1]

        raw_query = f"""
            WITH issue_activity_log AS ({query_string}),
            issue_activity_log_grouped AS (
                SELECT context_id,
                    timestamp,
                    user_id,
                    l.table,
                    entry_id,
                    jsonb_agg(jsonb_build_object(
                            'field',    field,
                            'action',   action,
                            'value',    value,
                            'value_id', value_id
                    )) AS changes
                FROM issue_activity_log l
                GROUP BY context_id, timestamp, user_id, l.table, entry_id
                ORDER BY timestamp
            )
            SELECT COUNT(*) FROM issue_activity_log_grouped ialg;
        """

        with connection.cursor() as cursor:
            cursor.execute(raw_query, params)
            row = cursor.fetchone()

        if row:
            return row[0]
        else:
            return 0


class NixpkgsIssueAggregatedLog(models.Model):
    objects = NixpkgsIssueAggregatedLogQueryManager()

    class Meta:
        managed = False
        db_table = "pghistory_context"

    id = models.BigIntegerField(primary_key=True)
    context = models.ForeignKey(
        Context, db_column="context_id", to_field="id", on_delete=models.DO_NOTHING
    )
    timestamp = models.DateTimeField(null=True, default=None)
    user = models.ForeignKey(
        User, db_column="user_id", to_field="id", on_delete=models.DO_NOTHING
    )
    table = models.CharField(max_length=256)
    entry = models.ForeignKey(
        NixpkgsIssue, db_column="entry_id", to_field="id", on_delete=models.DO_NOTHING
    )
    changes = models.JSONField()
