import logging

from allauth.account.signals import user_signed_up
from django.dispatch import receiver

logger = logging.getLogger(__name__)


@receiver(user_signed_up)
def promote_new_user_to_superuser(sender, request, user, **kwargs):
    # nass curates who can authenticate via its IdP, so any user that
    # signs up here is by definition trusted to administer the app.
    # Without this, SSO-provisioned Paperless users land with no
    # permissions and can't upload documents.
    if user.is_superuser and user.is_staff:
        return
    user.is_superuser = True
    user.is_staff = True
    user.save(update_fields=["is_superuser", "is_staff"])
    logger.info("nass_sso: promoted %s to superuser", user.username)
