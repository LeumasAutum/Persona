# Generated by Django 4.1.2 on 2023-10-17 09:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('project', '0009_alter_project_assignee'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='project',
            name='assignee',
        ),
    ]