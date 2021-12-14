from django.contrib import admin
from django.urls import path, include

from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Birthday book API",
        default_version='v1',
        description="Test description",
        terms_of_service="https://bdaybook.ru/policies/terms/",
        contact=openapi.Contact(email="supp.bdaybook@gmail.com"),
        license=openapi.License(name="Test License"),
    ),
    url='https://bdaybook.ru/',
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/auth/', include('authentication.urls')),
    path('api/v1/congratulations/', include('congratulation.urls')),
    path('api/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api/redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
