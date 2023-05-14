from django.contrib.auth.tokens import PasswordResetTokenGenerator
import django_six as six


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
                six.force_text(user.pk) + six.force_text(timestamp) +
                six.force_text(user.is_active)
        )


account_activation_token = TokenGenerator()
