from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models.signals import post_save, post_migrate
from django.dispatch import receiver
from django.core.management import call_command

# Custom User Manager
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        extra_fields.setdefault('is_verified', False)
        extra_fields.setdefault('is_suspended', False)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        # Assign role automatically
        if 'account_type' in extra_fields:
            role_name = extra_fields['account_type']
            role = Role.objects.filter(name=role_name).first()
            if role:
                user.role = role
                user.save()

        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('is_suspended', False)
        return self.create_user(email, password, **extra_fields)

# Role Model
class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

# Custom User Model
class CustomUser(AbstractUser):
    ACCOUNT_TYPES = [
        ('client', 'Client'),
        ('rental', 'Rental (Single Person)'),
        ('company', 'Company'),
        ('admin', 'Admin'),
    ]

    username =models.CharField(max_length=25)
    email = models.EmailField(unique=True)

    account_type = models.CharField(max_length=10, choices=ACCOUNT_TYPES, default='client')
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    otp = models.IntegerField(null=True, blank=True)
    keycloak_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_suspended = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Keep empty to only require email and password

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
