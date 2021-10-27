from django.urls import path

from .views import CongratulateListAPIView, CongratulateDetailAPIView


app_name = 'congratulations'

urlpatterns = [
    path('', CongratulateListAPIView.as_view(), name='congratulations'),
    path('<int:id>', CongratulateDetailAPIView.as_view(), name='congratulation'),

]