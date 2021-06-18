from django.urls.resolvers import URLPattern
from .views import ExpenseSummaryStats
from django.urls import path



urlpatterns = [
  path('expense_summary', ExpenseSummaryStats.as_view(), name="expense_summary")
]