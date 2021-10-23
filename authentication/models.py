from datetime import datetime

from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.db import models

from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):
    """
    Определим собственный класс Manager для кастомного пользователя
    """

    def create_user(self, email, password=None):
        """ Создает и возвращает пользователя с имэйлом, паролем и именем. """

        if not email:
            raise ValueError('Users must have an email address.')

        user = self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        """ Создает и возввращет пользователя с привилегиями суперадмина. """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """
    Определим модель поьзователя с полям "Email" и полями, опделяющими права доступа
    """

    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        db_index=True,
        unique=True
    )
    # Флаг определяет верифицирован ли ользоатель при регистрации
    is_verified = models.BooleanField(default=False)

    # Деактивиция учетной записи вместо ее полного удаления
    is_active = models.BooleanField(default=True)

    # Флаг определяет, кто может войти в административную часть
    is_staff = models.BooleanField(default=False)

    # Является ли пользователь адмиистратором
    is_admin = models.BooleanField(default=False)

    # Временная метка создания объекта.
    created_at = models.DateTimeField(auto_now_add=True)

    # Временная метка показывающая время последнего обновления объекта.
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'

    objects = UserManager()

    def __str__(self):
        """ Строковое представление модели (отображается в консоли) """
        return self.email

    def get_full_name(self):
        """
        Вместо полного имени возвращаем Email
        """
        return self.email

    def get_short_name(self):
        """ Вместо короткого имени возвращаем Email """
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'refresh_live': str(datetime.now() + refresh.lifetime),
            'access': str(refresh.access_token),
            'access_live': str(datetime.now() + refresh.access_token.lifetime),
        }
