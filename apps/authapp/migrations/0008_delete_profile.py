# Generated by Django 4.2 on 2024-09-23 06:56

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("authapp", "0007_profile"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Profile",
        ),
    ]
