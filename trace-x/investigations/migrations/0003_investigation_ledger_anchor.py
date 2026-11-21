from django.db import migrations, models


def backfill_anchors(apps, schema_editor):
    Investigation = apps.get_model("investigations", "Investigation")
    IntegrityRecord = apps.get_model("investigations", "IntegrityRecord")

    for investigation in Investigation.objects.all():
        records = IntegrityRecord.objects.filter(investigation=investigation).order_by("height")
        tip = records.last()
        investigation.ledger_length = records.count()
        investigation.ledger_tip = tip.block_hash if tip else ""
        investigation.save(update_fields=["ledger_length", "ledger_tip"])


class Migration(migrations.Migration):

    dependencies = [
        ("investigations", "0002_alter_integrityrecord_created_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="investigation",
            name="ledger_length",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="investigation",
            name="ledger_tip",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="investigation",
            name="analysis_signature",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="investigation",
            name="analysis_report",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_anchors, migrations.RunPython.noop),
    ]