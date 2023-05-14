from django.contrib import admin

from .models import Ad
from .models import Category


class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)


class AdAdmin(admin.ModelAdmin):
    list_display = ('title', 'category')
    list_filter = ('category',)
    search_fields = ('name__startswith',)


admin.site.register(Category, CategoryAdmin)
admin.site.register(Ad, AdAdmin)
