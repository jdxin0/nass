from django.apps import AppConfig


class NassSSOConfig(AppConfig):
    name = "nass_sso"
    verbose_name = "nass SSO helper"

    def ready(self):
        from . import signals  # noqa: F401
