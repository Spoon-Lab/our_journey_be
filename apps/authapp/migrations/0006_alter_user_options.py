# Generated by Django 4.2 on 2024-09-11 12:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("authapp", "0005_alter_user_options"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="user",
            options={"verbose_name": "user", "verbose_name_plural": "users"},
        ),
    ]
